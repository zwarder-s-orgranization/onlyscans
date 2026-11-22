package main

import (
	"testing"
)

func TestGraphQLDeclarativePluginsAndSavedNodes_Seam2(t *testing.T) {
	env := newGatewayTestEnv(t)

	// 1. Starter blueprints readable by VIEWER+.
	bpData := env.mustGraphQL(t, env.viewerToken, `{ declarativePluginBlueprints { id name description spec } }`, nil)
	bps := mustSlice(t, bpData["declarativePluginBlueprints"], "declarativePluginBlueprints")
	if len(bps) != 3 {
		t.Fatalf("len(declarativePluginBlueprints) = %d, want 3", len(bps))
	}

	// Mint a real scoped token to verify scoped tokens cannot run Test Bench or Saved Node mutations.
	tokData := env.mustGraphQL(t, env.ownerToken, `mutation {
		createScopedToken(input: { name: "ci-scoped-decl", scopes: ["ci:startRun", "ci:readRun"] }) {
			plaintextToken
		}
	}`, nil)
	scopedToken := mustString(t, mustMap(t, tokData["createScopedToken"], "createScopedToken")["plaintextToken"], "plaintextToken")

	// 2. Test Bench allowed for EDITOR, forbidden for VIEWER and scoped token.
	firstSpec := mustMap(t, bps[0], "blueprint[0]")["spec"]
	for _, tok := range []string{env.viewerToken, scopedToken} {
		_, g := env.postGraphQL(t, tok, `mutation($spec: JSON!) { testDeclarativePlugin(input: { declarativeSpec: $spec }) { ok summary } }`, map[string]any{"spec": firstSpec}, nil)
		if firstErrorCode(g.Errors) != "FORBIDDEN" {
			t.Fatalf("expected FORBIDDEN for testDeclarativePlugin, got %#v", g.Errors)
		}
	}
	tbData := env.mustGraphQL(t, env.editorToken, `mutation($spec: JSON!) {
		testDeclarativePlugin(input: {
			declarativeSpec: $spec
			files: [{ path: "application.yml", content: "management:\n  endpoints:\n    web:\n      exposure:\n        include: \"*\"\n" }]
		}) { ok summary durationMs activeOutputPorts }
	}`, map[string]any{"spec": firstSpec})
	tbRes := mustMap(t, tbData["testDeclarativePlugin"], "testDeclarativePlugin")
	if tbRes["ok"] != true {
		t.Fatalf("expected ok=true from testDeclarativePlugin, got %#v", tbRes)
	}

	// 3. EDITOR can create DECLARATIVE draft via installPlugin, but still FORBIDDEN on EXTERNAL_PULL.
	_, gDenied := env.postGraphQL(t, env.editorToken, `mutation { installPlugin(input: { name: "ext-denied", sourceMode: EXTERNAL_PULL }) { installation { id } } }`, nil, nil)
	if firstErrorCode(gDenied.Errors) != "FORBIDDEN" {
		t.Fatalf("expected FORBIDDEN for editor EXTERNAL_PULL installPlugin, got %#v", gDenied.Errors)
	}
	createdDecl := env.mustGraphQL(t, env.editorToken, `mutation($spec: JSON!) {
		installPlugin(input: { name: "decl-editor", sourceMode: DECLARATIVE, declarativeSpec: $spec, saveAsDraft: true }) {
			installation { id name sourceMode status pluginVersion }
		}
	}`, map[string]any{"spec": firstSpec})
	declInst := mustMap(t, mustMap(t, createdDecl["installPlugin"], "installPlugin")["installation"], "installation")
	if declInst["sourceMode"] != "DECLARATIVE" {
		t.Fatalf("sourceMode = %v, want DECLARATIVE", declInst["sourceMode"])
	}

	// 4. Saved Nodes CRUD + RBAC + duplicate conflict.
	for _, tok := range []string{env.viewerToken, scopedToken} {
		_, g := env.postGraphQL(t, tok, `mutation { saveNode(input: { name: "Denied", pluginId: "logic.filter", params: { minSeverity: "HIGH" } }) { id } }`, nil, nil)
		if firstErrorCode(g.Errors) != "FORBIDDEN" {
			t.Fatalf("expected FORBIDDEN for saveNode, got %#v", g.Errors)
		}
	}
	savedData := env.mustGraphQL(t, env.editorToken, `mutation {
		saveNode(input: { name: "High Filter", description: "Only high+", pluginId: "logic.filter", params: { minSeverity: "HIGH" } }) {
			id name pluginId canonicalParamsHash params
		}
	}`, nil)
	sn := mustMap(t, savedData["saveNode"], "saveNode")
	snID := mustString(t, sn["id"], "id")

	// Duplicate save returns CONFLICT.
	_, gDup := env.postGraphQL(t, env.editorToken, `mutation {
		saveNode(input: { name: "High Filter Dup", pluginId: "logic.filter", params: { minSeverity: "HIGH" } }) { id }
	}`, nil, nil)
	if firstErrorCode(gDup.Errors) != "CONFLICT" {
		t.Fatalf("expected CONFLICT for duplicate saveNode, got %#v", gDup.Errors)
	}

	// VIEWER can read savedNodes palette list.
	listData := env.mustGraphQL(t, env.viewerToken, `{ savedNodes { id name pluginId canonicalParamsHash } }`, nil)
	if len(mustSlice(t, listData["savedNodes"], "savedNodes")) != 1 {
		t.Fatalf("expected 1 savedNode, got %#v", listData["savedNodes"])
	}

	// EDITOR updates and deletes SavedNode cleanly.
	updData := env.mustGraphQL(t, env.editorToken, `mutation($id: ID!) {
		updateSavedNode(input: { id: $id, name: "Critical Filter", params: { minSeverity: "CRITICAL" } }) { id name }
	}`, map[string]any{"id": snID})
	if mustMap(t, updData["updateSavedNode"], "updateSavedNode")["name"] != "Critical Filter" {
		t.Fatalf("unexpected updated name: %#v", updData)
	}
	delData := env.mustGraphQL(t, env.editorToken, `mutation($id: ID!) { deleteSavedNode(id: $id) }`, map[string]any{"id": snID})
	if delData["deleteSavedNode"] != true {
		t.Fatalf("expected deleteSavedNode=true, got %#v", delData)
	}
}
