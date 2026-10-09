// SPDX-License-Identifier: GPL-2.0+
/*
 * Dan Williams <dcbw@redhat.com>
 *
 * Copyright (C) 2007 - 2021 Red Hat, Inc.
 */

#include "nm-default.h"
#include "nma-private.h"

#include <string.h>

#include "nma-eap.h"
#include "nma-eap-simple.h"
#include "nma-ws.h"
#include "nma-ws-private.h"
#include "nma-cert-chooser.h"
#include "utils.h"

#define I_NAME_COLUMN   0
#define I_METHOD_COLUMN 1

struct _NMAEapPeap {
	NMAEap parent;

	const char *password_flags_name;
	GtkSizeGroup *size_group;
	NMAWs8021x *ws_8021x;
	gboolean is_editor;
	GtkWidget *ca_cert_chooser;
	GtkWidget *eap_widget;
	/* The connection's actual ca-cert scheme at load time - used under TOFU
	 * to pick which field (chooser vs. hash) displays what's already pinned,
	 * independent of the "validation method" combo's own 0/1 selection. */
	NMSetting8021xCKScheme ca_scheme;
};

static char *peap_derive_anon_identity (NMAEapPeap *method);

static void
destroy (NMAEap *parent)
{
	NMAEapPeap *method = (NMAEapPeap *) parent;

	/* ws_8021x outlives this widget (it's shared across whatever EAP method
	 * is currently selected) - without this, switching Authentication away
	 * from PEAP leaves peap_update_anon_placeholder_cb connected with a
	 * dangling method pointer, called on the next "ws-changed". */
	g_signal_handlers_disconnect_by_data (method->ws_8021x, method);

	if (method->size_group)
		g_object_unref (method->size_group);
}

/* Accepts a hash pasted with common copy-paste formatting (colons, spaces,
 * mixed case, e.g. "AA:BB:CC:..." as shown by openssl/wpa_supplicant) and
 * strips it down to bare hex. Returns a newly allocated 64-char lowercase
 * hex string, or NULL if what remains isn't a valid SHA-256 fingerprint. */
static char *
clean_sha256_hex (const char *text)
{
	GString *out;
	int      i;

	if (!text)
		return NULL;

	out = g_string_sized_new (64);
	for (i = 0; text[i]; i++) {
		if (text[i] == ':' || g_ascii_isspace (text[i]))
			continue;
		if (!g_ascii_isxdigit (text[i])) {
			g_string_free (out, TRUE);
			return NULL;
		}
		g_string_append_c (out, g_ascii_tolower (text[i]));
	}

	if (out->len != 64) {
		g_string_free (out, TRUE);
		return NULL;
	}
	return g_string_free (out, FALSE);
}

static gboolean
validate (NMAEap *parent, GError **error)
{
	NMAEapPeap *method = (NMAEapPeap *) parent;
	GtkWidget *widget;
	GtkTreeModel *model;
	GtkTreeIter iter;
	NMAEap *eap = NULL;
	gboolean valid = FALSE;
	int active;

	/* "Validation method" combo: 0=TOFU, 1=CA cert+domain, 2=server hash,
	 * 3=no validation. Only the selected one (1 or 2) is checked here -
	 * TOFU and no validation need nothing from the user. */
	widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_peap_server_verify_combo"));
	active = gtk_combo_box_get_active (GTK_COMBO_BOX (widget));

	if (active == 2) {
		GtkWidget *hash_widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_peap_server_hash_entry"));
		gs_free char *cleaned = clean_sha256_hex (gtk_editable_get_text (GTK_EDITABLE (hash_widget)));

		if (!cleaned) {
			widget_set_error (hash_widget);
			g_set_error_literal (error, NMA_ERROR, NMA_ERROR_GENERIC,
			                     _("certificate hash must be 64 hex characters (SHA-256)"));
			return FALSE;
		}
	} else if (active == 1
	           && !nma_cert_chooser_validate (NMA_CERT_CHOOSER (method->ca_cert_chooser), error))
		return FALSE;

	widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_peap_inner_auth_combo"));
	g_assert (widget);

	model = gtk_combo_box_get_model (GTK_COMBO_BOX (widget));
	gtk_combo_box_get_active_iter (GTK_COMBO_BOX (widget), &iter);
	gtk_tree_model_get (model, &iter, I_METHOD_COLUMN, &eap, -1);
	g_assert (eap);
	valid = nma_eap_validate (eap, error);
	nma_eap_unref (eap);
	return valid;
}

static void
add_to_size_group (NMAEap *parent, GtkSizeGroup *group)
{
	NMAEapPeap *method = (NMAEapPeap *) parent;
	GtkWidget *widget;
	GtkTreeModel *model;
	GtkTreeIter iter;
	NMAEap *eap;

	if (method->size_group)
		g_object_unref (method->size_group);
	method->size_group = g_object_ref (group);

	widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_peap_anon_identity_label"));
	g_assert (widget);
	gtk_size_group_add_widget (group, widget);

	widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_peap_server_verify_method_label"));
	g_assert (widget);
	gtk_size_group_add_widget (group, widget);

	widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_peap_domain_label"));
	g_assert (widget);
	gtk_size_group_add_widget (group, widget);

	nma_cert_chooser_add_to_size_group (NMA_CERT_CHOOSER (method->ca_cert_chooser), group);

	widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_peap_version_label"));
	g_assert (widget);
	gtk_size_group_add_widget (group, widget);

	widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_peap_inner_auth_label"));
	g_assert (widget);
	gtk_size_group_add_widget (group, widget);

	widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_peap_inner_auth_combo"));
	g_assert (widget);

	model = gtk_combo_box_get_model (GTK_COMBO_BOX (widget));
	gtk_combo_box_get_active_iter (GTK_COMBO_BOX (widget), &iter);
	gtk_tree_model_get (model, &iter, I_METHOD_COLUMN, &eap, -1);
	g_assert (eap);
	nma_eap_add_to_size_group (eap, group);
	nma_eap_unref (eap);
}

static void
fill_connection (NMAEap *parent, NMConnection *connection)
{
	NMAEapPeap *method = (NMAEapPeap *) parent;
	NMSetting8021x *s_8021x;
	NMSetting8021xCKFormat format = NM_SETTING_802_1X_CK_FORMAT_UNKNOWN;
	GtkWidget *widget;
	const char *text;
	char *value = NULL;
	NMAEap *eap = NULL;
	GtkTreeModel *model;
	GtkTreeIter iter;
	int peapver_active = 0;
	GError *error = NULL;
	gboolean ca_cert_error = FALSE;
	NMSetting8021xCKScheme scheme = NM_SETTING_802_1X_CK_SCHEME_UNKNOWN;
	NMSettingSecretFlags secret_flags;
	GtkWidget *combo_widget;
	int active;

	s_8021x = nm_connection_get_setting_802_1x (connection);
	g_assert (s_8021x);

	nm_setting_802_1x_add_eap_method (s_8021x, "peap");

	widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_peap_anon_identity_entry"));
	g_assert (widget);
	text = gtk_editable_get_text (GTK_EDITABLE (widget));
	if (text && *text)
		g_object_set (s_8021x, NM_SETTING_802_1X_ANONYMOUS_IDENTITY, text, NULL);
	else {
		/* No explicit override: save the derived value itself rather than
		 * leaving the property unset for nm-supplicant-config.c to derive
		 * at connect time - keeps the saved profile explicit. */
		gs_free char *derived = peap_derive_anon_identity (method);

		g_object_set (s_8021x, NM_SETTING_802_1X_ANONYMOUS_IDENTITY, derived, NULL);
	}

	/* "Validation method" combo: 0=TOFU, 1=CA cert+domain, 2=server hash,
	 * 3=no validation. The single source of truth for all of the below -
	 * see peap_ca_cert_mode_changed_cb(). */
	combo_widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_peap_server_verify_combo"));
	active = gtk_combo_box_get_active (GTK_COMBO_BOX (combo_widget));

	g_object_set (s_8021x, NM_SETTING_802_1X_CA_VERIFY_MODE,
	              active == 0 ? NM_SETTING_802_1X_CA_VERIFY_MODE_TOFU
	                          : NM_SETTING_802_1X_CA_VERIFY_MODE_DEFAULT,
	              NULL);

	/* While TOFU owns the pin, the CA-chooser/domain/hash fields only display
	 * what TOFU already put in the connection (read-only, see
	 * peap_ca_cert_mode_changed_cb) - skip writing them so Save never
	 * clobbers TOFU's own ca-cert/domain-match with a copy of itself. */
	widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_peap_domain_entry"));
	g_assert (widget);
	if (active != 0) {
		/* Only meaningful in CA+domain mode (1); a leftover value typed
		 * there earlier must not be saved once a different mode is picked. */
		text = (active == 1) ? gtk_editable_get_text (GTK_EDITABLE (widget)) : NULL;
		g_object_set (s_8021x, NM_SETTING_802_1X_DOMAIN_SUFFIX_MATCH, (text && *text) ? text : NULL, NULL);
	}

	switch (active) {
	case 2:
		/* Manual server-hash pin: writes ca-cert=hash://server/sha256/<hex>
		 * directly via the same scheme TOFU uses for its own leaf-only pin
		 * (nm-supplicant-config.c handles it unconditionally, no
		 * ca-verify-mode involved), so wpa_supplicant enforces it with zero
		 * daemon changes. */
		widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_peap_server_hash_entry"));
		text = gtk_editable_get_text (GTK_EDITABLE (widget));
		{
			gs_free char *hex = clean_sha256_hex (text);
			gs_free char *hash_uri = hex ? g_strdup_printf ("hash://server/sha256/%s", hex) : NULL;

			/* validate() already blocks Save on an invalid hash; hex==NULL
			 * here only via update_secrets()/other callers that skip it. */
			if (hash_uri
			    && !nm_setting_802_1x_set_ca_cert (s_8021x, hash_uri, NM_SETTING_802_1X_CK_SCHEME_SERVER_HASH, NULL, &error)) {
				g_warning ("Couldn't set CA certificate hash: %s", error ? error->message : "(unknown)");
				g_clear_error (&error);
			}
			/* Clears a stale "no validation" ignore-flag an earlier edit of
			 * this same (possibly cached) connection object may have set -
			 * nma_eap_ca_cert_ignore_set() only checks filename != NULL, the
			 * hash string works fine for that. */
			if (hash_uri)
				nma_eap_ca_cert_ignore_set (parent, connection, hash_uri, FALSE);
		}
		break;
	case 3:
		/* No validation: explicitly drop any previously-set CA certificate
		 * and mark it as intentionally not required. */
		nm_setting_802_1x_set_ca_cert (s_8021x, NULL, NM_SETTING_802_1X_CK_SCHEME_UNKNOWN, NULL, NULL);
		nma_eap_ca_cert_ignore_set (parent, connection, NULL, FALSE);
		break;
	case 0:
		/* TOFU owns the cert; don't touch it. Just clear any leftover
		 * "no validation" flag from an earlier edit of this connection. */
		nma_eap_ca_cert_ignore_set (parent, connection, "tofu", FALSE);
		break;
	default: /* 1: CA certificate chooser */
		/* Save CA certificate PIN and its flags to the connection */
		secret_flags = nma_cert_chooser_get_cert_password_flags (NMA_CERT_CHOOSER (method->ca_cert_chooser));
		nm_setting_set_secret_flags (NM_SETTING (s_8021x), NM_SETTING_802_1X_CA_CERT_PASSWORD,
		                             secret_flags, NULL);
		if (method->is_editor) {
			/* Update secret flags and popup when editing the connection */
			nma_cert_chooser_update_cert_password_storage (NMA_CERT_CHOOSER (method->ca_cert_chooser),
			                                               secret_flags, NM_SETTING (s_8021x),
			                                               NM_SETTING_802_1X_CA_CERT_PASSWORD);
			g_object_set (s_8021x, NM_SETTING_802_1X_CA_CERT_PASSWORD,
			              nma_cert_chooser_get_cert_password (NMA_CERT_CHOOSER (method->ca_cert_chooser)),
			              NULL);
		}

		value = nma_cert_chooser_get_cert (NMA_CERT_CHOOSER (method->ca_cert_chooser), &scheme);
		format = NM_SETTING_802_1X_CK_FORMAT_UNKNOWN;
		if (!nm_setting_802_1x_set_ca_cert (s_8021x, value, scheme, &format, &error)) {
			g_warning ("Couldn't read CA certificate '%s': %s", value, error ? error->message : "(unknown)");
			g_clear_error (&error);
			ca_cert_error = TRUE;
		}
		nma_eap_ca_cert_ignore_set (parent, connection, value, ca_cert_error);
		g_free (value);
		break;
	}

	widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_peap_version_combo"));
	peapver_active = gtk_combo_box_get_active (GTK_COMBO_BOX (widget));
	switch (peapver_active) {
	case 1:  /* PEAP v0 */
		g_object_set (G_OBJECT (s_8021x), NM_SETTING_802_1X_PHASE1_PEAPVER, "0", NULL);
		break;
	case 2:  /* PEAP v1 */
		g_object_set (G_OBJECT (s_8021x), NM_SETTING_802_1X_PHASE1_PEAPVER, "1", NULL);
		break;
	default: /* Automatic */
		g_object_set (G_OBJECT (s_8021x), NM_SETTING_802_1X_PHASE1_PEAPVER, NULL, NULL);
		break;
	}

	widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_peap_inner_auth_combo"));
	model = gtk_combo_box_get_model (GTK_COMBO_BOX (widget));
	gtk_combo_box_get_active_iter (GTK_COMBO_BOX (widget), &iter);
	gtk_tree_model_get (model, &iter, I_METHOD_COLUMN, &eap, -1);
	g_assert (eap);

	nma_eap_fill_connection (eap, connection);
	nma_eap_unref (eap);
}

/* Mirrors nm-supplicant-config.c's own anonymous-identity derivation
 * (user@realm -> anonymous@realm, or "anonymous" with no realm). Returns a
 * newly allocated string; never NULL. */
static char *
peap_derive_anon_identity (NMAEapPeap *method)
{
	NMAEap *parent = (NMAEap *) method;
	GtkWidget *combo;
	GtkTreeModel *model;
	GtkTreeIter iter;
	NMAEap *eap = NULL;
	const char *username;
	const char *at;
	char *derived;

	combo = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_peap_inner_auth_combo"));
	if (!gtk_combo_box_get_active_iter (GTK_COMBO_BOX (combo), &iter))
		return g_strdup ("anonymous");
	model = gtk_combo_box_get_model (GTK_COMBO_BOX (combo));
	gtk_tree_model_get (model, &iter, I_METHOD_COLUMN, &eap, -1);
	if (!eap)
		return g_strdup ("anonymous");

	username = nma_eap_simple_get_username ((NMAEapSimple *) eap);
	at = (username && *username) ? strchr (username, '@') : NULL;
	derived = g_strdup_printf ("anonymous%s", at ? at : "");

	nma_eap_unref (eap);
	return derived;
}

/* Keeps the Anonymous identity placeholder showing exactly what NM will
 * actually send, live as the username is typed. Only ever a placeholder -
 * an explicit anonymous identity the user types always wins; if left blank,
 * fill_connection() saves this same derived value, not nothing. */
static void
peap_update_anon_placeholder_cb (NMAWs *ws, gpointer user_data)
{
	NMAEapPeap *method = (NMAEapPeap *) user_data;
	NMAEap *parent = (NMAEap *) method;
	GtkWidget *anon_widget;
	gs_free char *placeholder = peap_derive_anon_identity (method);

	/* "ws-changed" fires on every keystroke in any field, not just this
	 * username one - skip the set (and the redraw/flicker it causes) unless
	 * the placeholder text actually changed. */
	anon_widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_peap_anon_identity_entry"));
	if (g_strcmp0 (gtk_entry_get_placeholder_text (GTK_ENTRY (anon_widget)), placeholder) != 0)
		gtk_entry_set_placeholder_text (GTK_ENTRY (anon_widget), placeholder);
}

static void
inner_auth_combo_changed_cb (GtkWidget *combo, gpointer user_data)
{
	NMAEap *parent = (NMAEap *) user_data;
	NMAEapPeap *method = (NMAEapPeap *) parent;
	GtkBox *vbox;
	NMAEap *eap = NULL;
	GtkTreeModel *model;
	GtkTreeIter iter;

	vbox = GTK_BOX (gtk_builder_get_object (parent->builder, "eap_peap_inner_auth_vbox"));
	g_return_if_fail (vbox);

	/* Remove any previous wireless security widgets */
	if (method->eap_widget)
		gtk_box_remove (vbox, method->eap_widget);

	model = gtk_combo_box_get_model (GTK_COMBO_BOX (combo));
	gtk_combo_box_get_active_iter (GTK_COMBO_BOX (combo), &iter);
	gtk_tree_model_get (model, &iter, I_METHOD_COLUMN, &eap, -1);
	g_assert (eap);

	method->eap_widget = nma_eap_get_widget (eap);
	g_return_if_fail (method->eap_widget);
	gtk_widget_unparent (method->eap_widget);

	if (method->size_group)
		nma_eap_add_to_size_group (eap, method->size_group);
	gtk_box_append (vbox, method->eap_widget);

	nma_eap_unref (eap);

	peap_update_anon_placeholder_cb (NULL, method);
	nma_ws_changed_cb (combo, method->ws_8021x);
}

static GtkWidget *
inner_auth_combo_init (NMAEapPeap *method,
                       NMConnection *connection,
                       NMSetting8021x *s_8021x,
                       gboolean secrets_only)
{
	NMAEap *parent = (NMAEap *) method;
	GtkWidget *combo;
	GtkListStore *auth_model;
	GtkTreeIter iter;
	NMAEapSimple *em_mschap_v2;
	NMAEapSimple *em_md5;
	NMAEapSimple *em_gtc;
	guint32 active = 0;
	const char *phase2_auth = NULL;
	NMAEapSimpleFlags simple_flags;

	auth_model = gtk_list_store_new (2, G_TYPE_STRING, nma_eap_get_type ());

	if (s_8021x) {
		if (nm_setting_802_1x_get_phase2_auth (s_8021x))
			phase2_auth = nm_setting_802_1x_get_phase2_auth (s_8021x);
		else if (nm_setting_802_1x_get_phase2_autheap (s_8021x))
			phase2_auth = nm_setting_802_1x_get_phase2_autheap (s_8021x);
	}

	simple_flags = NMA_EAP_SIMPLE_FLAG_PHASE2;
	if (method->is_editor)
		simple_flags |= NMA_EAP_SIMPLE_FLAG_IS_EDITOR;
	if (secrets_only)
		simple_flags |= NMA_EAP_SIMPLE_FLAG_SECRETS_ONLY;

	em_mschap_v2 = nma_eap_simple_new (method->ws_8021x,
	                                   connection,
	                                   NMA_EAP_SIMPLE_TYPE_MSCHAP_V2,
	                                   simple_flags,
	                                   NULL);
	gtk_list_store_append (auth_model, &iter);
	gtk_list_store_set (auth_model, &iter,
	                    I_NAME_COLUMN, _("MSCHAPv2"),
	                    I_METHOD_COLUMN, em_mschap_v2,
	                    -1);
	nma_eap_unref (NMA_EAP (em_mschap_v2));

	/* Check for defaulting to MSCHAPv2 */
	if (phase2_auth && !strcasecmp (phase2_auth, "mschapv2"))
		active = 0;

	em_md5 = nma_eap_simple_new (method->ws_8021x,
	                             connection,
	                             NMA_EAP_SIMPLE_TYPE_MD5,
	                             simple_flags,
	                             NULL);
	gtk_list_store_append (auth_model, &iter);
	gtk_list_store_set (auth_model, &iter,
	                    I_NAME_COLUMN, _("MD5"),
	                    I_METHOD_COLUMN, em_md5,
	                    -1);
	nma_eap_unref (NMA_EAP (em_md5));

	/* Check for defaulting to MD5 */
	if (phase2_auth && !strcasecmp (phase2_auth, "md5"))
		active = 1;

	em_gtc = nma_eap_simple_new (method->ws_8021x,
	                             connection,
	                             NMA_EAP_SIMPLE_TYPE_GTC,
	                             simple_flags,
	                             NULL);
	gtk_list_store_append (auth_model, &iter);
	gtk_list_store_set (auth_model, &iter,
	                    I_NAME_COLUMN, _("GTC"),
	                    I_METHOD_COLUMN, em_gtc,
	                    -1);
	nma_eap_unref (NMA_EAP (em_gtc));

	/* Check for defaulting to GTC */
	if (phase2_auth && !strcasecmp (phase2_auth, "gtc"))
		active = 2;

	combo = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_peap_inner_auth_combo"));
	g_assert (combo);

	gtk_combo_box_set_model (GTK_COMBO_BOX (combo), GTK_TREE_MODEL (auth_model));
	g_object_unref (G_OBJECT (auth_model));
	gtk_combo_box_set_active (GTK_COMBO_BOX (combo), active);

	g_signal_connect (G_OBJECT (combo), "changed",
	                  (GCallback) inner_auth_combo_changed_cb,
	                  method);
	return combo;
}

static void
update_secrets (NMAEap *parent, NMConnection *connection)
{
	nma_eap_phase2_update_secrets_helper (parent,
	                                      connection,
	                                      "eap_peap_inner_auth_combo",
	                                      I_METHOD_COLUMN);
}

/* The "validation method" combo is the single source of truth: 0=TOFU,
 * 1=CA cert + domain, 2=server hash, 3=no validation (insecure). Previously two
 * separate checkboxes plus this combo had to be kept in sync by hand -
 * that drift between independently-set widgets was the root cause of nearly
 * every bug here. One index, nothing else to get out of sync.
 *
 * Visible and sensitive are driven by the exact same booleans below - never
 * computed separately. */
static void
peap_ca_cert_mode_changed_cb (GtkWidget *combo, gpointer user_data)
{
	NMAEapPeap *method = (NMAEapPeap *) user_data;
	GtkBuilder *builder = NMA_EAP (method)->builder;
	GtkWidget  *hash_entry    = GTK_WIDGET (gtk_builder_get_object (builder, "eap_peap_server_hash_entry"));
	GtkWidget  *domain_entry  = GTK_WIDGET (gtk_builder_get_object (builder, "eap_peap_domain_entry"));
	GtkWidget  *warning_label = GTK_WIDGET (gtk_builder_get_object (builder, "eap_peap_no_verify_warning_label"));
	int         active = gtk_combo_box_get_active (GTK_COMBO_BOX (combo));
	gboolean    is_tofu = active == 0;
	gboolean    editable = active == 1 || active == 2;
	/* Under TOFU, show whichever field matches what TOFU actually pinned
	 * (read-only) - that's its own scheme, not the combo's 1/2 choice,
	 * which the user never gets to make in TOFU mode. Nothing pinned yet
	 * (ca_scheme UNKNOWN, e.g. a brand-new connection) means neither
	 * field has anything to show, so both stay hidden. */
	gboolean    show_ca_group = active == 1
	                          || (is_tofu && (method->ca_scheme == NM_SETTING_802_1X_CK_SCHEME_BLOB
	                                         || method->ca_scheme == NM_SETTING_802_1X_CK_SCHEME_PATH));
	gboolean    show_hash     = active == 2
	                          || (is_tofu && method->ca_scheme == NM_SETTING_802_1X_CK_SCHEME_SERVER_HASH);

	gtk_widget_set_visible   (method->ca_cert_chooser, show_ca_group);
	gtk_widget_set_sensitive (method->ca_cert_chooser, show_ca_group && editable);

	gtk_widget_set_visible   (hash_entry, show_hash);
	gtk_widget_set_sensitive (hash_entry, show_hash && editable);

	/* domain-suffix-match only means anything alongside a CA certificate -
	 * same visibility/sensitivity as the chooser. */
	gtk_widget_set_visible   (domain_entry, show_ca_group);
	gtk_widget_set_sensitive (domain_entry, show_ca_group && editable);

	gtk_widget_set_visible (warning_label, active == 3);

	nma_ws_changed_cb (combo, method->ws_8021x);
}

NMAEapPeap *
nma_eap_peap_new (NMAWs8021x *ws_8021x,
                  NMConnection *connection,
                  gboolean is_editor,
                  gboolean secrets_only)
{
	NMAEap *parent;
	NMAEapPeap *method;
	GtkWidget *widget;
	NMSetting8021x *s_8021x = NULL;
	gboolean ca_not_required = FALSE;

	parent = nma_eap_init (NMA_WS (ws_8021x),
	                       sizeof (NMAEapPeap),
	                       validate,
	                       add_to_size_group,
	                       fill_connection,
	                       update_secrets,
	                       destroy,
	                       "/org/gnome/libnma/nma-eap-peap.ui",
	                       "eap_peap_grid",
	                       "eap_peap_anon_identity_entry",
	                       FALSE);
	if (!parent)
		return NULL;

	method = (NMAEapPeap *) parent;
	method->password_flags_name = NM_SETTING_802_1X_PASSWORD;
	method->ws_8021x = ws_8021x;
	method->is_editor = is_editor;

	if (connection)
		s_8021x = nm_connection_get_setting_802_1x (connection);

	widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_peap_grid"));
	g_assert (widget);

	method->ca_cert_chooser = nma_cert_chooser_new ("CA",
	                                                  NMA_CERT_CHOOSER_FLAG_CERT
	                                                | (secrets_only ? NMA_CERT_CHOOSER_FLAG_PASSWORDS : 0));
	gtk_grid_attach (GTK_GRID (widget), method->ca_cert_chooser, 0, 3, 2, 1);
	gtk_widget_show (method->ca_cert_chooser);

	g_signal_connect (method->ca_cert_chooser,
	                  "cert-validate",
	                  G_CALLBACK (nma_eap_ca_cert_validate_cb),
	                  NULL);
	g_signal_connect (method->ca_cert_chooser,
	                  "changed",
	                  G_CALLBACK (nma_ws_changed_cb),
	                  ws_8021x);

	nma_eap_setup_cert_chooser (NMA_CERT_CHOOSER (method->ca_cert_chooser), s_8021x,
	                            nm_setting_802_1x_get_ca_cert_scheme,
	                            nm_setting_802_1x_get_ca_cert_path,
	                            nm_setting_802_1x_get_ca_cert_uri,
	                            nm_setting_802_1x_get_ca_cert_password,
	                            NULL,
	                            NULL,
	                            NULL,
	                            NULL);

	if (connection && nma_eap_ca_cert_ignore_get (parent, connection)) {
		gchar *ca_cert;
		NMSetting8021xCKScheme scheme;

		ca_cert = nma_cert_chooser_get_cert (NMA_CERT_CHOOSER (method->ca_cert_chooser), &scheme);
		if (ca_cert)
			g_free (ca_cert);
		else
			ca_not_required = TRUE;
	}

	if (secrets_only)
		ca_not_required = TRUE;

	/* ca-verify-mode/domain-match are TOFU fork additions to libnm, newer than
	 * this project's NM_VERSION_MIN_REQUIRED floor; nothing to deprecate here. */
	G_GNUC_BEGIN_IGNORE_DEPRECATIONS

	{
		GtkWidget *method_combo = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_peap_server_verify_combo"));
		GtkWidget *hash_entry   = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_peap_server_hash_entry"));
		gboolean   tofu_active;
		gboolean   no_verify_active;
		int        active;

		g_assert (method_combo);
		g_assert (hash_entry);

		method->ca_scheme = s_8021x ? nm_setting_802_1x_get_ca_cert_scheme (s_8021x) : NM_SETTING_802_1X_CK_SCHEME_UNKNOWN;
		tofu_active = s_8021x
		            && nm_setting_802_1x_get_ca_verify_mode (s_8021x) == NM_SETTING_802_1X_CA_VERIFY_MODE_TOFU;
		no_verify_active = ca_not_required && !tofu_active;

		/* Combo starting index follows the connection's actual state - TOFU
		 * and "no validation" take priority since they override whatever
		 * ca-cert scheme happens to be stored. A profile with nothing
		 * configured at all (no cert, no hash - UNKNOWN scheme, which is
		 * also what a brand-new s_8021x reads as) also defaults to TOFU;
		 * an existing CA-cert blob/path connection still shows as such. */
		if (tofu_active)
			active = 0;
		else if (no_verify_active)
			active = 3;
		else if (method->ca_scheme == NM_SETTING_802_1X_CK_SCHEME_SERVER_HASH)
			active = 2;
		else if (method->ca_scheme == NM_SETTING_802_1X_CK_SCHEME_UNKNOWN)
			active = 0;
		else
			active = 1;
		gtk_combo_box_set_active (GTK_COMBO_BOX (method_combo), active);

		/* Pre-fill the hash field whenever the connection is actually
		 * pinned by hash, TOFU-pinned or user-entered alike. */
		if (method->ca_scheme == NM_SETTING_802_1X_CK_SCHEME_SERVER_HASH) {
			const char *uri = nm_setting_802_1x_get_ca_cert_uri (s_8021x);
			const char *prefix = "hash://server/sha256/";

			if (uri && g_str_has_prefix (uri, prefix))
				gtk_editable_set_text (GTK_EDITABLE (hash_entry), uri + strlen (prefix));
		}

		g_signal_connect (method_combo, "changed", G_CALLBACK (peap_ca_cert_mode_changed_cb), method);

		/* Apply the visibility/sensitivity rules derived above now that the
		 * combo holds its initial state (no signal has fired yet). */
		peap_ca_cert_mode_changed_cb (method_combo, method);
	}

	G_GNUC_END_IGNORE_DEPRECATIONS

	widget = inner_auth_combo_init (method, connection, s_8021x, secrets_only);
	inner_auth_combo_changed_cb (widget, (gpointer) method);

	widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_peap_version_combo"));
	g_assert (widget);
	gtk_combo_box_set_active (GTK_COMBO_BOX (widget), 0);
	if (s_8021x) {
		const char *peapver;

		peapver = nm_setting_802_1x_get_phase1_peapver (s_8021x);
		if (peapver) {
			/* Index 0 is "Automatic" */
			if (!strcmp (peapver, "0"))
				gtk_combo_box_set_active (GTK_COMBO_BOX (widget), 1);
			else if (!strcmp (peapver, "1"))
				gtk_combo_box_set_active (GTK_COMBO_BOX (widget), 2);
		}
	}

	widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_peap_anon_identity_entry"));
	if (s_8021x && nm_setting_802_1x_get_anonymous_identity (s_8021x))
		gtk_editable_set_text (GTK_EDITABLE (widget), nm_setting_802_1x_get_anonymous_identity (s_8021x));
	/* Placeholder is kept live by peap_update_anon_placeholder_cb(), already
	 * set once above via inner_auth_combo_changed_cb() and kept in sync with
	 * the username field from here via the "ws-changed" connection below. */
	g_signal_connect (ws_8021x, "ws-changed", G_CALLBACK (peap_update_anon_placeholder_cb), method);

	widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_peap_domain_entry"));
	if (s_8021x && nm_setting_802_1x_get_domain_suffix_match (s_8021x))
		gtk_editable_set_text (GTK_EDITABLE (widget), nm_setting_802_1x_get_domain_suffix_match (s_8021x));

	if (secrets_only) {
		widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_peap_anon_identity_entry"));
		gtk_widget_hide (widget);
		widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_peap_domain_entry"));
		gtk_widget_hide (widget);
		widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_peap_no_verify_warning_label"));
		gtk_widget_hide (widget);
		widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_peap_server_verify_method_label"));
		gtk_widget_hide (widget);
		widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_peap_server_verify_combo"));
		gtk_widget_hide (widget);
		widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_peap_server_hash_entry"));
		gtk_widget_hide (widget);
		widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_peap_inner_auth_combo"));
		gtk_widget_hide (widget);
		widget = GTK_WIDGET (gtk_builder_get_object (parent->builder, "eap_peap_version_combo"));
		gtk_widget_hide (widget);
	}

	return method;
}
