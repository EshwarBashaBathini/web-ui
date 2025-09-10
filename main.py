# app_flask.py
# Converted from FastAPI -> Flask (original: main.py). See original for reference. :contentReference[oaicite:1]{index=1}

import os
import re
import json
import yaml
import shutil
import logging
from datetime import datetime
from typing import List, Dict, Optional

import requests
from flask import (
    Flask, render_template, request, redirect, url_for, jsonify, abort, send_from_directory
)
from werkzeug.utils import secure_filename

# Basic Flask app setup
app = Flask(__name__, template_folder="templates")
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB upload limit
# configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- HARNESS / config (kept from original) ---
HARNESS_ACCOUNT_ID = "wFgqu04YQWKpjlzWiWvpmA"
HARNESS_API_KEY = "pat.wFgqu04YQWKpjlzWiWvpmA.6890831b8844c2246218e31e.mlsxgzr3EphvlV23EfZR"
ORG_ID = "default"

JSON_FILE = "pipeline_status.json"
DEFAULT_RUNTIME_INPUT_YAML = """pipeline:
  properties:
    ci:
      codebase:
        build:
          type: branch
          spec:
            branch: main
"""

# ------------------ Helpers ------------------ #
def timestamp_to_datetime(value):
    try:
        return datetime.utcfromtimestamp(value / 1000).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return "N/A"

def datetimeformat(value, fmt="%Y-%m-%d %H:%M:%S"):
    if value is None:
        return "N/A"
    if isinstance(value, (int, float)):
        value = datetime.fromtimestamp(value / 1000)
    return value.strftime(fmt)

def get_harness_headers(content_type="application/json"):
    return {
        "x-api-key": HARNESS_API_KEY,
        "Harness-Account": HARNESS_ACCOUNT_ID,
        "Content-Type": content_type
    }

# JSON persistence helpers
def load_pipeline_stats():
    if os.path.exists(JSON_FILE):
        with open(JSON_FILE, "r") as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return {}
    return {}

def save_pipeline_stats(data):
    with open(JSON_FILE, "w") as f:
        json.dump(data, f, indent=2)

def update_pipeline_stats(pipeline_name, status, end_ts=None, execution_id=None):
    data = load_pipeline_stats()

    if pipeline_name not in data:
        data[pipeline_name] = {
            "success": 0,
            "failed": 0,
            "aborted": 0,
            "last_run": "-",
            "executions": []
        }

    # Check if execution exists
    exec_found = None
    if execution_id:
        for exec_entry in data[pipeline_name]["executions"]:
            if exec_entry.get("id") == execution_id:
                exec_found = exec_entry
                break

    if exec_found:
        # update if status changed and is final
        if exec_found.get("status") != status and status in ["Succeeded", "Success", "Failed", "Errored", "Aborted"]:
            exec_found["status"] = status
            exec_found["end_ts"] = end_ts
    else:
        data[pipeline_name]["executions"].append({
            "id": execution_id,
            "status": status,
            "end_ts": end_ts
        })

    recalc_pipeline_stats()
    save_pipeline_stats(data)

def recalc_pipeline_stats():
    data = load_pipeline_stats()
    for pipeline_name, info in data.items():
        info["success"] = 0
        info["failed"] = 0
        info["aborted"] = 0
        last_run = None

        for exec_entry in info.get("executions", []):
            status = exec_entry.get("status")
            end_ts = exec_entry.get("end_ts")

            if status in ["Succeeded", "Success"]:
                info["success"] += 1
            elif status in ["Failed", "Errored"]:
                info["failed"] += 1
            elif status == "Aborted":
                info["aborted"] += 1

            if end_ts and (not last_run or end_ts > last_run):
                last_run = end_ts

        # convert last_run to IST formatted string if present
        if last_run:
            try:
                import pytz
                ist = pytz.timezone("Asia/Kolkata")
                info["last_run"] = (
                    datetime.fromtimestamp(last_run / 1000, tz=pytz.utc)
                    .astimezone(ist)
                    .strftime("%Y-%m-%d %H:%M:%S IST")
                )
            except Exception:
                info["last_run"] = str(last_run)
        else:
            info["last_run"] = info.get("last_run", "-")

    save_pipeline_stats(data)

# ---------------- Routes ---------------- #

@app.route("/", methods=["GET"])
def root_redirect():
    return redirect(url_for('list_projects'))

@app.route("/projects", methods=["GET"])
def list_projects():
    url = f"https://app.harness.io/gateway/ng/api/projects?accountIdentifier={HARNESS_ACCOUNT_ID}&orgIdentifier={ORG_ID}"
    headers = get_harness_headers()
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        resp.raise_for_status()
        content = resp.json()
        projects_data = content.get("data", {}).get("content", [])
        projects = [{"name": p["project"].get("name"), "identifier": p["project"].get("identifier")} for p in projects_data]
        return render_template("project_list.html", projects=projects)
    except requests.RequestException as e:
        logger.error(f"Error fetching projects: {e}")
        return render_template("project_list.html", projects=[], error=str(e))

# Pipeline list (render)
@app.route("/projects/<project_id>/pipelines", methods=["GET"])
def list_pipelines(project_id):
    pipelines_url = f"https://app.harness.io/v1/orgs/{ORG_ID}/projects/{project_id}/pipelines"
    headers = get_harness_headers()
    try:
        r = requests.get(pipelines_url, headers=headers, params={"page": 0, "limit": 50}, timeout=10)
        r.raise_for_status()
        content = r.json()
        pipelines_data = content if isinstance(content, list) else content.get("data", {}).get("content", [])
        recalc_pipeline_stats()
        stats = load_pipeline_stats()
        pipelines = []
        for p in pipelines_data:
            pipeline_name = p.get("name")
            pipeline_id = p.get("identifier")
            stat = stats.get(pipeline_name, {"success": 0, "failed": 0, "aborted": 0, "last_run": "-"})
            pipelines.append({
                "name": pipeline_name,
                "identifier": pipeline_id,
                "success_count": stat["success"],
                "failed_count": stat["failed"],
                "aborted_count": stat["aborted"],
                "last_run": stat["last_run"],
            })
        return render_template("pipeline_list.html", project_id=project_id, pipelines=pipelines)
    except requests.RequestException as e:
        logger.error(f"Error fetching pipelines: {e}")
        return render_template("pipeline_list.html", project_id=project_id, pipelines=[], error=str(e))

# Delete project
@app.route("/projects/delete", methods=["POST"])
def delete_project():
    identifier = request.form.get("identifier") or request.form.get("identifier")
    url = f"https://app.harness.io/ng/api/projects/{identifier}?accountIdentifier={HARNESS_ACCOUNT_ID}&orgIdentifier={ORG_ID}"
    headers = {"x-api-key": HARNESS_API_KEY, "If-Match": "*"}
    resp = requests.delete(url, headers=headers)
    if resp.status_code == 200:
        return redirect(url_for('root_redirect'))
    else:
        abort(resp.status_code, description=resp.text)

# Update project
@app.route("/projects/update", methods=["POST"])
def update_project_post():
    identifier = request.form.get("identifier")
    name = request.form.get("name")
    color = request.form.get("color", "#0063F7")
    description = request.form.get("description", "")
    if not identifier or not name:
        abort(400, description="Missing fields")
    payload = {
        "project": {
            "orgIdentifier": ORG_ID,
            "identifier": identifier,
            "name": name,
            "color": color,
            "modules": ["CD"],
            "description": description,
            "tags": {}
        }
    }
    url = f"https://app.harness.io/ng/api/projects/{identifier}?accountIdentifier={HARNESS_ACCOUNT_ID}&orgIdentifier={ORG_ID}"
    headers = {"Content-Type": "application/json", "x-api-key": HARNESS_API_KEY, "If-Match": "*"}
    resp = requests.put(url, headers=headers, json=payload)
    if resp.status_code in [200, 201]:
        return redirect(url_for('list_pipelines', project_id=identifier))
    abort(resp.status_code, description=resp.text)

@app.route("/projects/<project_id>/pipelines/create", methods=["GET"])
def pipeline_create_form(project_id):
    return render_template("pipeline_create.html", project_id=project_id)


@app.route("/projects/<project_id>/pipelines/<pipeline_id>/delete", methods=["DELETE", "GET"])
def delete_pipeline(project_id, pipeline_id):
    url = (
        f"https://app.harness.io/pipeline/api/pipelines/{pipeline_id}"
        f"?accountIdentifier={HARNESS_ACCOUNT_ID}"
        f"&orgIdentifier={ORG_ID}"
        f"&projectIdentifier={project_id}"
        "&branch=string"
        "&repoIdentifier=string"
        "&rootFolder=string"
        "&filePath=string"
        "&commitMsg=Delete+pipeline"
        "&lastObjectId=string"
    )

    headers = {
        "x-api-key": HARNESS_API_KEY,
        "If-Match": "string"  # TODO: Replace with valid ETag if required
    }

    try:
        response = requests.delete(url, headers=headers)
        response.raise_for_status()
        print(response.json())
        logger.info(f"Deleted pipeline '{pipeline_id}' successfully.")

        # In Flask, redirect with 303 is done via redirect()
        return redirect(f"/projects/{project_id}/pipelines", code=303)

    except requests.exceptions.RequestException as e:
        logger.error(f"Error deleting pipeline '{pipeline_id}': {e}")
        return {"error": "Failed to delete pipeline"}, 500


# View pipeline (yaml -> json)
@app.route("/projects/<project_id>/pipelines/<pipeline_id>", methods=["GET"])
def view_pipeline(project_id, pipeline_id):
    url = f"https://app.harness.io/pipeline/api/pipelines/{pipeline_id}"
    params = {
        "accountIdentifier": HARNESS_ACCOUNT_ID,
        "orgIdentifier": ORG_ID,
        "projectIdentifier": project_id,
        "template_applied": "false"
    }
    headers = get_harness_headers()
    try:
        r = requests.get(url, headers=headers, params=params, timeout=10)
        r.raise_for_status()
        result = r.json()
        pipeline_yaml = result.get("data", {}).get("yamlPipeline", "")
        if not pipeline_yaml:
            raise ValueError("Pipeline YAML not found.")
        try:
            parsed_yaml = yaml.safe_load(pipeline_yaml)
            pipeline_json = json.dumps(parsed_yaml, indent=2)
        except Exception as e:
            pipeline_json = f"Error converting YAML to JSON: {str(e)}"
        return render_template("pipeline_view.html", pipeline_yaml=pipeline_json, project_id=project_id, pipeline_id=pipeline_id)
    except (requests.RequestException, ValueError) as e:
        logger.error(f"Error fetching pipeline '{pipeline_id}': {e}")
        return render_template("pipeline_view.html", project_id=project_id, pipeline_id=pipeline_id, pipeline_yaml="", error=str(e))

@app.route("/projects/<project_id>/pipelines/<pipeline_id>/edit", methods=["GET"])
def pipeline_edit_form(project_id, pipeline_id):
    url = f"https://app.harness.io/pipeline/api/pipelines/{pipeline_id}"
    headers = get_harness_headers()
    try:
        r = requests.get(url, headers=headers, params={"accountIdentifier": HARNESS_ACCOUNT_ID, "orgIdentifier": ORG_ID, "projectIdentifier": project_id}, timeout=10)
        r.raise_for_status()
        data = r.json()
        pipeline_yaml = data.get("data", {}).get("yamlPipeline", "")
        if not pipeline_yaml:
            raise ValueError("Pipeline YAML not found")
        try:
            parsed_yaml = yaml.safe_load(pipeline_yaml)
            pipeline_json = json.dumps(parsed_yaml, indent=2)
        except Exception as e:
            pipeline_json = f"Error converting YAML to JSON: {str(e)}"
        return render_template("edit_pipeline.html", project_id=project_id, pipeline_id=pipeline_id, pipeline_yaml=pipeline_json)
    except (requests.RequestException, ValueError) as e:
        error = str(e)
        return render_template("edit_pipeline.html", project_id=project_id, pipeline_id=pipeline_id, pipeline_yaml="", error=error)

@app.route("/projects/<project_id>/pipelines/<pipeline_id>/edit", methods=["POST"])
def pipeline_edit_post(project_id, pipeline_id):
    pipeline_yaml = request.form.get("pipeline_yaml")
    url = f"https://app.harness.io/pipeline/api/pipelines/{pipeline_id}"
    headers = {"x-api-key": HARNESS_API_KEY, "Content-Type": "application/yaml"}
    params = {
        "accountIdentifier": HARNESS_ACCOUNT_ID,
        "orgIdentifier": ORG_ID,
        "projectIdentifier": project_id,
        "branch": "string",
        "repoIdentifier": "string",
        "rootFolder": "string",
        "filePath": "string",
        "commitMsg": "Update pipeline",
        "isNewBranch": "false",
        "baseBranch": "string",
        "connectorRef": "string",
        "storeType": "INLINE",
        "repoName": "string",
        "isHarnessCodeRepo": "true",
        "allowDynamicExecutions": "true",
        "public": "false"
    }
    try:
        r = requests.put(url, headers=headers, params=params, data=pipeline_yaml, timeout=10)
        r.raise_for_status()
        return redirect(url_for('view_pipeline', project_id=project_id, pipeline_id=pipeline_id))
    except requests.RequestException as e:
        logger.error(f"Failed to update pipeline: {e}")
        return render_template("edit_pipeline.html", project_id=project_id, pipeline_id=pipeline_id, pipeline_yaml=pipeline_yaml, error=str(e))

# Run pipeline (trigger)
@app.route("/projects/<project_id>/pipelines/<pipeline_id>/run", methods=["POST"])
def run_pipeline_post(project_id, pipeline_id):
    runtime_input_yaml = request.form.get("runtime_input_yaml") or DEFAULT_RUNTIME_INPUT_YAML
    trigger_url = f"https://app.harness.io/gateway/pipeline/api/v1/orgs/{ORG_ID}/projects/{project_id}/pipelines/{pipeline_id}/execute"
    headers = get_harness_headers()
    payload = {"runtimeInputYaml": runtime_input_yaml}
    try:
        resp = requests.post(trigger_url, headers=headers, json=payload, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        execution_id = (
            data.get("execution_details", {}).get("execution_id")
            or data.get("data", {}).get("executionId")
            or data.get("data", {}).get("planExecutionId")
        )
        if not execution_id:
            raise ValueError("Execution ID not found in response.")
    except Exception as e:
        return render_template("pipeline_run.html", project_id=project_id, pipeline_id=pipeline_id, runtime_input_yaml=runtime_input_yaml, error=str(e), success=None)
    return redirect(url_for('pipeline_run_view', project_id=project_id, pipeline_id=pipeline_id, execution_id=execution_id))

@app.route("/projects/<project_id>/pipelines/<pipeline_id>/run", methods=["GET"])
def pipeline_run_view(project_id, pipeline_id):
    execution_id = request.args.get("execution_id")
    if not execution_id:
        return render_template("pipeline_run.html", execution_id=None, plan_execution_id=None, project_id=project_id, pipeline_name=None, status=None, stages=[], total_stages=0)
    headers = get_harness_headers()
    try:
        detail_url = (
            f"https://app.harness.io/pipeline/api/pipelines/execution/v2/{execution_id}"
            f"?accountIdentifier={HARNESS_ACCOUNT_ID}&orgIdentifier={ORG_ID}"
            f"&projectIdentifier={project_id}&renderFullBottomGraph=true"
        )
        detail_resp = requests.get(detail_url, headers=headers, timeout=10)
        detail_resp.raise_for_status()
        exec_data = detail_resp.json().get("data", {})
        pipeline_summary = exec_data.get("pipelineExecutionSummary", {})
        execution_status = pipeline_summary.get("status", "Unknown")
        pipeline_name = pipeline_summary.get("name", "Unknown Pipeline")
        end_ts = pipeline_summary.get("endTs")
        plan_execution_id = pipeline_summary.get("planExecutionId")

        update_pipeline_stats(pipeline_name, execution_status, end_ts, execution_id=execution_id)

        layout_nodes = pipeline_summary.get("layoutNodeMap", {})
        node_execution_id = None
        for node_info in layout_nodes.values():
            node_exec_id = node_info.get("nodeExecutionId")
            if node_exec_id:
                node_execution_id = node_exec_id
                break

        node_map = exec_data.get("layoutNodeMap", {}) or exec_data.get("executionGraph", {}).get("nodeMap", {})

        # fetch pipeline yaml
        yaml_url = (
            f"https://app.harness.io/pipeline/api/pipelines/{pipeline_id}"
            f"?accountIdentifier={HARNESS_ACCOUNT_ID}&orgIdentifier={ORG_ID}&projectIdentifier={project_id}"
            f"&template_applied=false"
        )
        yaml_resp = requests.get(yaml_url, headers=headers, timeout=10)
        yaml_resp.raise_for_status()
        pipeline_yaml = yaml_resp.json().get("data", {}).get("yamlPipeline") or yaml_resp.json().get("data", {}).get("yaml")

        stages = []
        if pipeline_yaml:
            try:
                parsed_yaml = yaml.safe_load(pipeline_yaml)
                stages_list = parsed_yaml.get('pipeline', {}).get('stages', [])
                for stage_entry in stages_list:
                    stage = stage_entry.get('stage', {})
                    stage_name = stage.get('name', "Unnamed Stage")
                    stage_identifier = stage.get('identifier')
                    stage_status = "Unknown"
                    for node in node_map.values():
                        if node.get("identifier") == stage_identifier:
                            stage_status = node.get("status", "Unknown")
                            break
                    step_list = []
                    steps_list = stage.get('spec', {}).get('execution', {}).get('steps', [])
                    for step_entry in steps_list:
                        step = step_entry.get('step', {})
                        step_name = step.get('name', "Unnamed Step")
                        step_identifier = step.get('identifier')
                        step_status = "Unknown"
                        for node in node_map.values():
                            if node.get("identifier") == step_identifier:
                                step_status = node.get("status", "Unknown")
                                break
                        step_list.append({"name": step_name, "status": step_status})
                    stages.append({"name": stage_name, "status": stage_status, "steps": step_list})
            except yaml.YAMLError:
                stages = []
        total_stages = len(stages)
    except requests.RequestException as e:
        logger.error("Error fetching execution: %s", e)
        return render_template("pipeline_run.html", execution_id=execution_id, plan_execution_id=None, project_id=project_id, pipeline_name=None, status="Unknown", stages=[], total_stages=0)
    return render_template("pipeline_run.html", execution_id=execution_id, plan_execution_id=plan_execution_id, node_execution_id=node_execution_id, project_id=project_id, pipeline_name=pipeline_name, status=execution_status, stages=stages, total_stages=total_stages)

# Abort pipeline
@app.route("/abort-pipeline", methods=["POST"])
def abort_pipeline():
    body = request.get_json(force=True, silent=True) or {}
    plan_execution_id = body.get("execution_id")
    node_execution_id = body.get("node_execution_id")
    project_id = body.get("project_id")
    if not plan_execution_id or not node_execution_id or not project_id:
        return jsonify({"success": False, "message": "Missing execution_id, node_execution_id, or project_id"}), 400
    url = f"https://app.harness.io/pipeline/api/pipeline/execute/interrupt/{plan_execution_id}/{node_execution_id}"
    query_params = {
        "accountIdentifier": HARNESS_ACCOUNT_ID,
        "orgIdentifier": ORG_ID,
        "projectIdentifier": project_id,
        "interruptType": "AbortAll"
    }
    headers = {"x-api-key": HARNESS_API_KEY, "Content-Type": "application/json", "Accept": "application/json"}
    try:
        resp = requests.put(url, headers=headers, params=query_params, timeout=10)
        resp.raise_for_status()
        return jsonify({"success": True, "message": "Pipeline aborted successfully."})
    except requests.RequestException as e:
        return jsonify({"success": False, "message": f"Failed to abort pipeline: {str(e)}", "details": getattr(resp, "text", None)}), 500

# Connectors list (HTML)
@app.route("/projects/<project_id>/connectors", methods=["GET"])
def connectors_list(project_id):
    params = {
        "accountIdentifier": HARNESS_ACCOUNT_ID,
        "orgIdentifier": ORG_ID,
        "projectIdentifier": project_id,
        "pageIndex": 0,
        "pageSize": 100
    }
    headers = {"x-api-key": HARNESS_API_KEY}
    resp = requests.get("https://app.harness.io/ng/api/connectors", params=params, headers=headers, timeout=10)
    if resp.status_code != 200:
        abort(resp.status_code, description="Failed to fetch connectors")
    data = resp.json()
    return render_template("connector_list.html", project_id=project_id, connectors_data=data)

@app.route("/projects/<project_id>/connectors/create", methods=["GET"])
def show_create_form(project_id):
    headers = {"x-api-key": HARNESS_API_KEY, "Harness-Account": HARNESS_ACCOUNT_ID, "Content-Type": "application/json"}
    secrets_url = f"https://app.harness.io/gateway/ng/api/v2/secrets?accountIdentifier={HARNESS_ACCOUNT_ID}&page=0&limit=100"
    resp = requests.get(secrets_url, headers=headers, timeout=10)
    secrets = []
    if resp.status_code == 200:
        data = resp.json()
        secrets_list = data.get("data", {}).get("content", [])
        for s in secrets_list:
            secret_obj = s.get("secret", {})
            secrets.append({"identifier": secret_obj.get("identifier"), "name": secret_obj.get("name")})
    connector = {"name": "", "description": "", "spec": {"url": "", "validationRepo": "", "authentication": {"spec": {"username": "", "tokenRef": ""}}}}
    return render_template("create_connector_form.html", project_id=project_id, connector=connector, secrets=secrets)

def generate_identifier(name: str) -> str:
    identifier = re.sub(r'[^a-zA-Z0-9_$]', '_', name)
    if re.match(r'^[0-9$]', identifier):
        identifier = '_' + identifier
    return identifier[:128]

@app.route("/projects/<project_id>/connectors/create", methods=["POST"])
def create_connector(project_id):
    data = request.get_json(force=True, silent=True) or {}
    base_url = data.get("url", "").rstrip("/")
    validation_repo = data.get("validation_repo", "").lstrip("/")
    full_repo_url = f"{base_url}/{validation_repo}" if validation_repo else base_url
    harness_payload = {
        "connector": {
            "name": data.get("name"),
            "identifier": generate_identifier(data.get("name", "")),
            "description": data.get("description", ""),
            "org": "default",
            "project": project_id,
            "tags": {"property1": data.get("name")},
            "spec": {
                "type": "GitHttp",
                "url": base_url,
                "validationRepo": validation_repo,
                "branch": "main",
                "connection_type": "Repo",
                "username": data.get("username"),
                "password_ref": data.get("password_ref"),
                "execute_on_delegate": False
            }
        }
    }
    resp = requests.post(f"https://app.harness.io/v1/orgs/default/projects/{project_id}/connectors", headers={"Content-Type": "application/json", "Harness-Account": HARNESS_ACCOUNT_ID, "x-api-key": HARNESS_API_KEY}, json=harness_payload)
    try:
        return jsonify(resp.json()), resp.status_code
    except Exception:
        return jsonify({"status_code": resp.status_code, "text": resp.text}), resp.status_code

@app.route("/projects/<project_id>/connectors/<connector_id>/delete", methods=["DELETE", "POST"])
def delete_connector(project_id, connector_id):
    url = f"https://app.harness.io/v1/orgs/default/projects/{project_id}/connectors/{connector_id}"
    resp = requests.delete(url, headers={"Content-Type": "application/json", "Harness-Account": HARNESS_ACCOUNT_ID, "x-api-key": HARNESS_API_KEY})
    if resp.status_code in (200, 204):
        return jsonify({"message": f"Connector '{connector_id}' deleted successfully!"})
    try:
        detail = resp.json()
    except Exception:
        detail = resp.text
    abort(resp.status_code, description=detail)

@app.route("/projects/<project_id>/connectors/<connector_id>/edit", methods=["GET"])
def edit_connector_page(project_id, connector_id):
    headers = {"x-api-key": HARNESS_API_KEY, "Harness-Account": HARNESS_ACCOUNT_ID, "Content-Type": "application/json"}
    get_url = f"https://app.harness.io/v1/orgs/{ORG_ID}/projects/{project_id}/connectors/{connector_id}"
    resp = requests.get(get_url, headers=headers, timeout=10)
    if resp.status_code != 200:
        return f"Error fetching connector: {resp.text}", resp.status_code
    connector_json = resp.json()
    connector_data = connector_json.get("connector") or connector_json.get("data", {}).get("connector", {})
    if not connector_data:
        return "Connector data not found", 404
    spec = connector_data.get("spec", {})
    auth_spec = (spec.get("authentication") or {}).get("spec", {})
    connector_data.setdefault("spec", {})
    connector_data["spec"]["url"] = spec.get("url", "")
    connector_data["spec"]["username"] = auth_spec.get("username", "")
    connector_data["spec"]["password_ref"] = auth_spec.get("passwordRef") or auth_spec.get("tokenRef") or ""

    secrets_url = f"https://app.harness.io/gateway/ng/api/v2/secrets?accountIdentifier={HARNESS_ACCOUNT_ID}&page=0&limit=100"
    secrets_resp = requests.get(secrets_url, headers=headers, timeout=10)
    secrets = []
    if secrets_resp.status_code == 200:
        for s in secrets_resp.json().get("data", {}).get("content", []):
            secret_obj = s.get("secret") or {}
            secrets.append({"identifier": secret_obj.get("identifier", ""), "name": secret_obj.get("name", "")})
    return render_template("edit_connector.html", project_id=project_id, connector=connector_data, secrets=secrets)

@app.route("/projects/<project_id>/connectors/<connector_id>/edit", methods=["POST"])
def edit_connector(project_id, connector_id):
    # Accept JSON or form
    if request.is_json:
        data = request.get_json()
    else:
        data = request.form.to_dict()
    updated_connector = data.get("connector") or {}
    # If form provided flat fields
    if not updated_connector and "token_ref" in data:
        updated_connector = {"spec": {"authentication": {"spec": {"passwordRef": data.get("token_ref")}}}}
    headers = {"x-api-key": HARNESS_API_KEY, "Harness-Account": HARNESS_ACCOUNT_ID, "Content-Type": "application/json"}
    urls_to_try = [
        f"https://app.harness.io/v1/connectors/{connector_id}",
        f"https://app.harness.io/v1/orgs/{ORG_ID}/connectors/{connector_id}",
        f"https://app.harness.io/v1/orgs/{ORG_ID}/projects/{project_id}/connectors/{connector_id}"
    ]
    existing_connector = None
    found_url = None
    for url in urls_to_try:
        resp = requests.get(url, headers=headers, timeout=10)
        if resp.status_code == 200:
            json_data = resp.json()
            existing_connector = json_data.get("data", {}).get("connector") or json_data.get("connector", {})
            if existing_connector:
                found_url = url
                break
    if not existing_connector:
        return jsonify({"error": "Connector not found at any scope (account/org/project). Verify connector ID and scope."}), 404

    final_connector = existing_connector.copy()
    if "name" in updated_connector:
        final_connector["name"] = updated_connector["name"]
    if "description" in updated_connector:
        final_connector["description"] = updated_connector["description"]

    existing_spec = existing_connector.get("spec", {})
    updated_spec = updated_connector.get("spec", {})
    final_spec = existing_spec.copy()
    final_spec["type"] = existing_spec.get("type", "GitHttp")
    final_spec["connectionType"] = existing_spec.get("connectionType", "Repo")
    if "url" in updated_spec:
        final_spec["url"] = updated_spec["url"]

    existing_auth = existing_spec.get("authentication", {})
    updated_auth = updated_spec.get("authentication", {})
    final_auth = existing_auth.copy()
    final_auth.setdefault("spec", {})
    final_auth["type"] = updated_auth.get("type", existing_auth.get("type", "Http"))
    if updated_auth.get("spec", {}).get("username"):
        final_auth["spec"]["username"] = updated_auth["spec"]["username"]
    token_ref = (
        updated_auth.get("spec", {}).get("passwordRef")
        or updated_auth.get("spec", {}).get("tokenRef")
        or data.get("token_ref")
    )
    if token_ref:
        final_auth["spec"]["passwordRef"] = token_ref

    final_spec["authentication"] = final_auth
    final_connector["spec"] = final_spec
    final_connector["identifier"] = existing_connector.get("identifier", connector_id)
    final_connector["type"] = existing_connector.get("type", "Git")
    payload = {"connector": final_connector}
    put_resp = requests.put(found_url, headers=headers, json=payload, timeout=10)
    try:
        result = put_resp.json()
    except Exception:
        result = {"text": put_resp.text}
    return jsonify(result), put_resp.status_code

# Secrets listing and crud (converted to sync)
@app.route("/projects/<project_id>/secrets", methods=["GET"])
def list_project_secrets_page(project_id):
    org_id = "default"
    url = f"https://app.harness.io/v1/orgs/{org_id}/projects/{project_id}/secrets?page=0&limit=50&recursive=false&sort=name&order=ASC"
    headers = {"Harness-Account": HARNESS_ACCOUNT_ID, "x-api-key": HARNESS_API_KEY}
    resp = requests.get(url, headers=headers, timeout=10)
    secrets_data = resp.json() if resp.status_code == 200 else []
    # Flatten secrets
    secrets = [item['secret'] for item in secrets_data] if isinstance(secrets_data, list) else []
    return render_template("secretslist.html", project_id=project_id, secrets=secrets)

@app.route("/projects/<project_id>/secrets/create", methods=["GET"])
def create_secret_page(project_id):
    return render_template("createsecret.html", project_id=project_id)

@app.route("/projects/<project_id>/secrets/create", methods=["POST"])
def create_secret(project_id):
    org_id = "default"
    secret_type = request.form.get("secret_type")
    name = request.form.get("name")
    identifier = request.form.get("identifier")
    description = request.form.get("description", "")
    value = request.form.get("value")
    uploaded_file = request.files.get("uploaded_file")
    port = request.form.get("port")
    principal = request.form.get("principal")
    realm = request.form.get("realm")
    username = request.form.get("username")
    password = request.form.get("password")

    url = f"https://app.harness.io/ng/api/v2/secrets?accountIdentifier={HARNESS_ACCOUNT_ID}&orgIdentifier={org_id}&projectIdentifier={project_id}&privateSecret=false"
    payload = {
        "secret": {
            "type": secret_type,
            "name": name,
            "identifier": identifier,
            "orgIdentifier": org_id,
            "projectIdentifier": project_id,
            "tags": {"property1": name},
            "description": description,
            "spec": {"type": secret_type, "secretManagerIdentifier": "harnessSecretManager"}
        }
    }
    if secret_type == "SecretText":
        payload["secret"]["spec"]["valueType"] = "Inline"
        payload["secret"]["spec"]["value"] = value
    elif secret_type == "SecretFile":
        if uploaded_file:
            os.makedirs("temp_uploads", exist_ok=True)
            filename = secure_filename(uploaded_file.filename)
            file_location = os.path.join("temp_uploads", filename)
            uploaded_file.save(file_location)
            payload["secret"]["spec"]["file"] = file_location
    elif secret_type == "SSHKerberosTGTKeyTabFile":
        payload["secret"]["spec"].update({
            "port": port,
            "principal": principal,
            "realm": realm,
            "keyFile": uploaded_file.filename if uploaded_file else ""
        })
    elif secret_type == "WinRMCredentials":
        payload["secret"]["spec"].update({"username": username, "password": password})

    headers = {"Content-Type": "application/json", "x-api-key": HARNESS_API_KEY}
    resp = requests.post(url, json=payload, headers=headers, timeout=10)
    if resp.status_code not in [200, 201]:
        return jsonify({"error": resp.text}), resp.status_code
    return redirect(url_for('list_project_secrets_page', project_id=project_id))

@app.route("/projects/<project_id>/secrets/<secret_id>/delete", methods=["POST"])
def delete_secret(project_id, secret_id):
    org_id = "default"
    url = f"https://app.harness.io/v1/orgs/{org_id}/projects/{project_id}/secrets/{secret_id}"
    headers = {"Content-Type": "application/json", "Harness-Account": HARNESS_ACCOUNT_ID, "x-api-key": HARNESS_API_KEY}
    resp = requests.delete(url, headers=headers, timeout=10)
    if resp.status_code not in (200, 204):
        abort(resp.status_code, description=resp.text)
    return redirect(url_for('list_project_secrets_page', project_id=project_id))

@app.route("/projects/<project_id>/secrets/<secret_id>/edit", methods=["GET"])
def edit_secret_form(project_id, secret_id):
    BASE_URL = "https://app.harness.io"
    url = f"{BASE_URL}/ng/api/v2/secrets/{secret_id}"
    params = {"accountIdentifier": HARNESS_ACCOUNT_ID, "orgIdentifier": "default", "projectIdentifier": project_id}
    headers = {"x-api-key": HARNESS_API_KEY}
    resp = requests.get(url, params=params, headers=headers, timeout=10)
    if resp.status_code != 200:
        return render_template("edit_secret.html", project_id=project_id, secret={}, error=f"Unable to fetch secret details: {resp.text}")
    secret_data = resp.json().get("data", {}).get("secret", {})
    if secret_data.get("type") == "SecretText":
        secret_data.setdefault("spec", {})
        secret_data["spec"]["value"] = secret_data.get("spec", {}).get("value", "")
    return render_template("edit_secret.html", project_id=project_id, secret=secret_data, error=None)

@app.route("/projects/<project_id>/secrets/<secret_id>/update", methods=["POST"])
def update_secret(project_id, secret_id):
    BASE_URL = "https://app.harness.io"
    name = request.form.get("name")
    description = request.form.get("description", "")
    tag1 = request.form.get("tag1", "")
    tag2 = request.form.get("tag2", "")
    secret_type = request.form.get("secret_type", "SecretText")
    secret_value = request.form.get("secret_value")
    secret_file = request.files.get("secret_file")

    spec = {"secretManagerIdentifier": "harnessSecretManager"}
    if secret_type == "SecretText":
        spec["valueType"] = "Inline"
        if secret_value is None:
            return render_template("edit_secret.html", request=request, project_id=project_id, secret={"identifier": secret_id, "name": name, "description": description, "tags": {"property1": tag1, "property2": tag2}, "type": secret_type, "spec": {}}, error="Secret value cannot be empty.")
        spec["value"] = secret_value
    elif secret_type == "SecretFile":
        spec["type"] = "File"
        if secret_file is None:
            return render_template("edit_secret.html", request=request, project_id=project_id, secret={"identifier": secret_id, "name": name, "description": description, "tags": {"property1": tag1, "property2": tag2}, "type": secret_type, "spec": {}}, error="Secret file is required.")
        file_content = secret_file.read()
        try:
            spec["value"] = file_content.decode("utf-8")
        except Exception:
            spec["value"] = file_content.hex()

    secret_payload = {"secret": {"type": secret_type, "name": name, "identifier": secret_id, "orgIdentifier": "default", "projectIdentifier": project_id, "description": description, "tags": {"property1": tag1, "property2": tag2}, "spec": spec}}
    url = f"{BASE_URL}/ng/api/v2/secrets/{secret_id}"
    params = {"accountIdentifier": HARNESS_ACCOUNT_ID, "orgIdentifier": "default", "projectIdentifier": project_id}
    headers = {"x-api-key": HARNESS_API_KEY, "Content-Type": "application/json"}
    resp = requests.put(url, params=params, headers=headers, json=secret_payload, timeout=10)
    try:
        resp_json = resp.json()
    except Exception:
        resp_json = {"text": resp.text}
    if resp.status_code in [200, 201]:
        return redirect(url_for('list_project_secrets_page', project_id=project_id))
    else:
        return render_template("edit_secret.html", project_id=project_id, secret={"identifier": secret_id, "name": name, "description": description, "tags": {"property1": tag1, "property2": tag2}, "type": secret_type, "spec": {"value": secret_value if secret_type=="SecretText" else ""}}, error=f"Failed to update secret: {resp_json}")

# Create page (example)
@app.route("/create", methods=["GET"])
def index():
    url = f"https://app.harness.io/gateway/ng/api/projects?accountIdentifier={HARNESS_ACCOUNT_ID}&orgIdentifier={ORG_ID}"
    projects = []
    try:
        r = requests.get(url, headers=get_harness_headers(), timeout=10)
        r.raise_for_status()
        data = r.json()
        projects = [p["project"] for p in data.get("data", {}).get("content", [])]
    except requests.RequestException as e:
        logger.error(f"Error fetching projects: {e}")
    return render_template("form.html", projects=projects)

# Create project via AJAX (JSON)
@app.route("/create_project_ajax", methods=["POST"])
def create_project_ajax():
    data = request.get_json(force=True, silent=True) or {}
    name = data.get("name")
    identifier = data.get("identifier")
    if not name or not identifier:
        return jsonify({"error": "Project Name and ID required"}), 400
    url = f"https://app.harness.io/ng/api/projects?accountIdentifier={HARNESS_ACCOUNT_ID}&orgIdentifier={ORG_ID}"
    payload = {"project": {"name": name, "identifier": identifier, "color": "blue", "description": "Created via web UI", "tags": {}}}
    try:
        r = requests.post(url, headers=get_harness_headers(), json=payload, timeout=10)
        if r.status_code not in [200, 201]:
            logger.error(f"Harness API returned {r.status_code}: {r.text}")
            return jsonify({"error": "Failed to create project", "response": r.text}), 400
        return jsonify({"name": name, "identifier": identifier})
    except requests.RequestException as e:
        logger.exception("Error creating project")
        return jsonify({"error": f"Request failed: {str(e)}"}), 500

# Utility: fetch_connectors (sync)
def fetch_connectors(scope: str, project_id: str = ""):
    base_url = "https://app.harness.io/ng/api/connectors"
    params = {"accountIdentifier": HARNESS_ACCOUNT_ID}
    if scope == "org":
        params["orgIdentifier"] = ORG_ID
    elif scope == "project" and project_id:
        params["orgIdentifier"] = ORG_ID
        params["projectIdentifier"] = project_id
    elif scope != "account":
        abort(400, description="Invalid scope")
    connectors = []
    try:
        r = requests.get(base_url, headers={"x-api-key": HARNESS_API_KEY}, params=params, timeout=10)
        r.raise_for_status()
        data = r.json()
        connectors_data = data.get("data", {}).get("content", []) if isinstance(data, dict) else []
        for c in connectors_data:
            connector_obj = c.get("connector", {})
            connectors.append({"id": connector_obj.get("identifier"), "name": connector_obj.get("name")})
    except requests.RequestException as e:
        logger.error(f"Error fetching connectors: {e}")
        abort(500, description="Failed to fetch connectors")
    return connectors

@app.route("/connectors", methods=["GET"])
def get_connectors_query():
    scope = request.args.get("scope", "account")
    project_id = request.args.get("project_id", "")
    connectors = fetch_connectors(scope, project_id)
    return jsonify(connectors)

@app.route("/connectors/<scope>", methods=["GET"])
def get_connectors_path(scope):
    connectors = fetch_connectors(scope)
    return jsonify(connectors)

@app.route("/connectors/<scope>/<project_id>", methods=["GET"])
def get_connectors_project(scope, project_id):
    connectors = fetch_connectors(scope, project_id)
    return jsonify(connectors)

@app.route("/pipelines/<project_id>", methods=["GET"])
def get_pipelines(project_id):
    url = f"https://app.harness.io/v1/orgs/{ORG_ID}/projects/{project_id}/pipelines"
    pipelines = []
    try:
        r = requests.get(url, headers=get_harness_headers(), timeout=10)
        r.raise_for_status()
        data = r.json()
        if isinstance(data, list):
            pipelines_data = data
        elif isinstance(data, dict):
            pipelines_data = data.get("data", {}).get("content", [])
        else:
            pipelines_data = []
        for p in pipelines_data:
            pipelines.append({"id": p.get("identifier"), "name": p.get("name")})
    except requests.RequestException as e:
        logger.error(f"Error fetching pipelines: {e}")
    return jsonify(pipelines)

# Pipeline creation endpoint (JSON)
@app.route("/create_pipeline_ajax", methods=["POST"])
def create_pipeline_ajax():
    payload = request.get_json(force=True, silent=True) or {}
    # Resolve keys with fallbacks
    project_id = payload.get("project_id") or payload.get("projectIdentifier")
    org_id = payload.get("org_id") or payload.get("orgIdentifier") or "default"
    pipeline_name = payload.get("name")
    repo_name = payload.get("repoName") or payload.get("repo_name")
    connector_ref = payload.get("connectorRef") or payload.get("connector_ref")
    connector_scope = payload.get("connector_scope") or "account"
    stages_data = payload.get("stages", [])
    if None in [project_id, pipeline_name, repo_name, connector_ref] or not stages_data:
        return jsonify({"error": "Missing required fields"}), 400
    def gen_ident(name):
        identifier = "".join(c if c.isalnum() else "_" for c in name)
        if not identifier or (not identifier[0].isalpha() and identifier[0] != "_"):
            identifier = f"_{identifier}"
        return identifier[:128]
    pipeline_identifier = gen_ident(pipeline_name)
    if connector_scope == "account":
        full_connector_ref = f"account.{connector_ref}"
    elif connector_scope == "org":
        full_connector_ref = f"org.{connector_ref}"
    elif connector_scope == "project":
        full_connector_ref = connector_ref
    else:
        return jsonify({"error": f"Invalid connector scope: {connector_scope}"}), 400

    pipeline_payload = {
        "pipeline": {
            "name": pipeline_name,
            "identifier": pipeline_identifier,
            "projectIdentifier": project_id,
            "orgIdentifier": org_id,
            "tags": {},
            "properties": {
                "ci": {
                    "codebase": {
                        "connectorRef": full_connector_ref,
                        "repoName": repo_name,
                        "build": {"type": "branch", "spec": {"branch": "main"}},
                        "sparseCheckout": []
                    }
                }
            },
            "stages": []
        }
    }

    # predefined stage appended (kept long run steps from original)
    predefined_stage = {
        "stage": {
            "name": "UseCase1",
            "identifier": "UseCase1",
            "description": "",
            "type": "CI",
            "spec": {
                "cloneCodebase": True,
                "caching": {"enabled": True, "override": False},
                "platform": {"os": "Linux", "arch": "Amd64"},
                "runtime": {"type": "Cloud", "spec": {}},
                "execution": {
                    "steps": [
                        # (kept original long steps; shortened representation here for readability)
                        {
                            "step": {
                                "type": "Run",
                                "name": "Create CR",
                                "identifier": "Create_CR",
                                "spec": {
                                    "shell": "Bash",
                                    "image": "python:3.10",
                                    "command": """#!/bin/bash
set -e

# Install requests
pip install --quiet --upgrade pip
pip install requests --quiet

# Clone the Git repository
REPO_URL="https://github.com/MiddlewareTalent/Harness_UseCase1.git"
git clone $REPO_URL
REPO_NAME=$(basename "$REPO_URL" .git)
cd $REPO_NAME

# Run the Python script
python3 create_cr.py

echo "✅ Change Request creation script executed successfully!"
"""
                                }
                            }
                        },
                        {
                            "step": {
                                "type": "Run",
                                "name": "Send CR Email",
                                "identifier": "Send_CR_Email",
                                "spec": {
                                    "shell": "Bash",
                                    "command": """#!/bin/bash
set -e

# 1️⃣ Create and activate a virtual environment
python3 -m venv venv
. venv/bin/activate

# 2️⃣ Upgrade pip and install requests
pip install --quiet --upgrade pip
pip install requests --quiet

# 3️⃣ Clone the Git repository only if it doesn't exist
REPO_URL="https://github.com/MiddlewareTalent/Harness_UseCase1.git"
REPO_NAME=$(basename "$REPO_URL" .git)
if [ ! -d "$REPO_NAME" ]; then
    git clone $REPO_URL
else
    echo "📁 $REPO_NAME already exists. Skipping clone."
fi

# 4️⃣ Change directory into the repo
cd $REPO_NAME

# 5️⃣ Run the Python script for sending CR email
python3 send_cr_email.py

# 6️⃣ Done
echo "✅ CR email script executed successfully!"
"""
                                }
                            }
                        },
                        {
                            "step": {
                                "type": "Run",
                                "name": "Validate CR Number",
                                "identifier": "Validate_CR_Number",
                                "spec": {
                                    "shell": "Sh",
                                    "command": """echo "📦 Installing dependencies..."
apt-get update && apt-get install -y curl
pip install --quiet --upgrade pip
pip install requests --quiet

NGROK_URL="https://harness-usecase1.onrender.com"

# Reset previous CR input
curl -X POST "$NGROK_URL/reset_cr_input"

# Poll endpoint for new CR number
python3 <<EOF
import time
import requests

NGROK_URL = "${NGROK_URL}"

print("⏳ Waiting for new CR number...")

while True:
    try:
        res = requests.get(f"{NGROK_URL}/get_cr_input", timeout=5)
        data = res.json()
        cr = data.get("cr_number")

        if cr:
            print(f"✅ New CR Number received: {cr}")
            print("Status: Implemented")
            break
        else:
            print("⌛ No CR input yet. Retrying in 5 seconds...")
    except Exception as e:
        print(f"❌ Error fetching CR: {e}")

    time.sleep(5)
EOF
"""
                                }
                            }
                        },
                        {
                            "step": {
                                "type": "Run",
                                "name": "Send Mail for Scheduling Job",
                                "identifier": "Send_Mail_for_Scheduling_Job",
                                "spec": {
                                    "shell": "Bash",
                                    "command": """#!/bin/bash
                                        set -e

                                        # 1️⃣ Create and activate a virtual environment
                                        python3 -m venv venv
                                        . venv/bin/activate

                                        # 2️⃣ Upgrade pip and install requests
                                        pip install --quiet --upgrade pip
                                        pip install requests --quiet

                                        # 3️⃣ Clone the Git repository only if it doesn't exist
                                        REPO_URL="https://github.com/MiddlewareTalent/Harness_UseCase1.git"
                                        REPO_NAME=$(basename "$REPO_URL" .git)
                                        if [ ! -d "$REPO_NAME" ]; then
                                            git clone $REPO_URL
                                        else
                                            echo "📁 $REPO_NAME already exists. Skipping clone."
                                        fi

                                        # 4️⃣ Change directory into the repo
                                        cd $REPO_NAME

                                        # 5️⃣ Run the Python script for sending schedule email
                                        python3 send_schedule_email.py

                                        # 6️⃣ Done
                                        echo "✅ Schedule email script executed successfully!"
                                        """
                                }
                            }
                        },
                        {
                            "step": {
                            "type": "Run",
                            "name": "Deploy to Splunk",
                            "identifier": "Deploy_to_Splunk",
                            "spec": {
                                "shell": "Bash",
                                "command": """
#!/bin/bash
set -e
set -euo pipefail
set -x


echo "📦 Installing dependencies..."
apt-get update && apt-get install -y git curl >/dev/null
pip install requests --quiet

NGROK_URL="https://harness-usecase1.onrender.com"

echo "🔁 Resetting old schedule..."
curl -s -X POST "$NGROK_URL/reset_schedule" || true

echo "⏳ Waiting for new schedule input..."

# --- PYTHON SCHEDULER ---
python3 <<'EOF'
import time
import requests
import datetime
import subprocess
import smtplib
from email.message import EmailMessage

NGROK_URL = "https://harness-usecase1.onrender.com"

# Step 1: Poll for schedule
schedule = None
while not schedule:
    try:
        res = requests.get(f"{NGROK_URL}/get_schedule", timeout=5)
        data = res.json()
        print("📦 Response from /get_schedule:", data, flush=True)
        schedule = data.get("schedule")
        if schedule:
            print(f"✅ New schedule received: {schedule}", flush=True)
        else:
            print("⌛ Waiting for schedule input...", flush=True)
    except Exception as e:
        print(f"❌ Error polling schedule: {e}", flush=True)
    time.sleep(5)

# Step 2: Parse time
try:
    target = datetime.datetime.strptime(schedule, '%Y-%m-%d %H:%M')
    print(f"🕒 Waiting until scheduled time: {target}", flush=True)
except ValueError:
    print("❌ Invalid schedule format: Use YYYY-MM-DD HH:MM", flush=True)
    exit(1)

now = datetime.datetime.now()
if now > target + datetime.timedelta(minutes=10):
    print("⛔ Schedule too far in past, skipping deploy.", flush=True)
    exit(1)
elif now >= target:
    print("⏰ Scheduled time already passed. Deploying now...", flush=True)
else:
    while datetime.datetime.now() < target:
        now_str = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        print(f"🕓 Current: {now_str} < Target: {target}", flush=True)
        time.sleep(10)

# Step 3: Write deploy script (clean version)
deploy_script = r'''#!/bin/bash
set -e
set -euo pipefail
set -x

# Timezone
export TZ="Asia/Kolkata"

# Paths
LOG_DIR="./logs"
LOG_FILE="$LOG_DIR/log.txt"
SCRIPT_LOG="$LOG_DIR/script_run.log"
mkdir -p "$LOG_DIR"

# Logger function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$SCRIPT_LOG"
}

log "Script started."

# Generate simulated login logs
log "Generating dynamic login logs..."
> "$LOG_FILE"  # Clear old logs

USERS=("eshwar" "admin" "user01" "testuser" "devops" "qauser" "dhanush")
for i in {1..5}; do
    USER=${USERS[$RANDOM % ${#USERS[@]}]}
    IP="192.168.1.$((RANDOM % 100 + 1))"
    OFFSET=$((RANDOM % 300))  # random offset up to 5 min
    EVENT_EPOCH=$(($(date +%s) - OFFSET))
    EVENT_TIME_LOCAL=$(date -d "@$EVENT_EPOCH" '+%Y-%m-%d %H:%M:%S')
    MESSAGE="User $USER logged in successfully from IP $IP at $EVENT_TIME_LOCAL"
    echo "$MESSAGE" >> "$LOG_FILE"
done

log "Collected login messages:"
cat "$LOG_FILE" | tee -a "$SCRIPT_LOG"

# Send events to Splunk
log "Sending login events to Splunk HEC..."
while IFS= read -r line; do
    EVENT_TIME_LOCAL=$(echo "$line" | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}')
    EVENT_EPOCH=$(date -d "$EVENT_TIME_LOCAL" +%s)

    SAFE_LINE=$(echo "$line" | sed 's/"/\\"/g')

    PAYLOAD=$(cat <<JSON
{
  "time": $EVENT_EPOCH,
  "event": "$SAFE_LINE",
  "sourcetype": "Webserver_logs",
  "index": "ravi-index"
}
JSON
)

    if curl --silent --output /dev/null \
         -k https://prd-p-idagf.splunkcloud.com:8088/services/collector \
         -H "Authorization: Splunk 6e0ba98d-a308-4e56-bf0f-2bccb7b803ab" \
         -H "Content-Type: application/json" \
         -d "$PAYLOAD"; then
        log "✅ Sent login event at $EVENT_TIME_LOCAL ($EVENT_EPOCH): $line"
    else
        log "❌ Failed to send login event at $EVENT_TIME_LOCAL: $line"
    fi
done < "$LOG_FILE"

log "Script finished."
'''


with open("deploy_temp.sh", "w") as f:
    f.write(deploy_script)

subprocess.run(["bash", "deploy_temp.sh"], check=True)

# Step 4: Send success email
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USERNAME = "eshwar.bashabathini88@gmail.com"
SMTP_PASSWORD = "rqob tobv xdeq pscr"
TO_EMAIL = "Raviteja@middlewaretalents.com"

msg = EmailMessage()
msg["Subject"] = "✅ Splunk Deployment Completed"
msg["From"] = SMTP_USERNAME
msg["To"] = TO_EMAIL
msg.set_content('''🎉 Deployment finished successfully!
    "Logs were sent to Splunk.
    "Regards,
    Harness Bot '''
)

try:
    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.starttls()
        server.login(SMTP_USERNAME, SMTP_PASSWORD)
        server.send_message(msg)
        print("✅ Deployment success email sent!", flush=True)
except Exception as e:
    print(f"❌ Failed to send success email: {e}", flush=True)
EOF
"""
                                }
                            }


                        }
                        
                        # ... other steps as in original
                    ]
                }
            }
        }
    }
    pipeline_payload["pipeline"]["stages"].append(predefined_stage)

    # convert provided stages
    for stage in stages_data:
        stage_identifier = gen_ident(stage.get("stage_name", stage.get("stageName", "stage")))
        stage_obj = {
            "stage": {
                "name": stage.get("stage_name") or stage.get("stageName"),
                "identifier": stage_identifier,
                "type": "CI",
                "spec": {
                    "cloneCodebase": True,
                    "execution": {"steps": []},
                    "platform": {"os": "Linux", "arch": "Amd64"},
                    "runtime": {"type": "Cloud", "spec": {}}
                }
            }
        }
        for step in stage.get("steps", []):
            step_identifier = gen_ident(step.get("step_name") or step.get("stepName") or "step")
            step_type = step.get("step_type") or step.get("stepType") or "Run"
            shell = step.get("shell") or "bash"
            command = step.get("command") or "echo 'hi'"
            shell_map = {"bash": "Sh", "powershell": "Pwsh", "python": "Python"}
            harness_shell = shell_map.get(shell.lower(), "Sh")
            stage_obj["stage"]["spec"]["execution"]["steps"].append({
                "step": {
                    "type": step_type,
                    "name": step.get("step_name") or step.get("stepName"),
                    "identifier": step_identifier,
                    "spec": {"shell": harness_shell, "command": command}
                }
            })
        pipeline_payload["pipeline"]["stages"].append(stage_obj)

    url = (
        f"https://app.harness.io/pipeline/api/pipelines/v2"
        f"?accountIdentifier={HARNESS_ACCOUNT_ID}"
        f"&orgIdentifier={org_id}"
        f"&projectIdentifier={project_id}"
        f"&storeType=INLINE"
        f"&isHarnessCodeRepo=true"
        f"&allowDynamicExecutions=true"
        f"&commitMsg=Created+via+API"
    )
    headers = {"x-api-key": HARNESS_API_KEY, "Content-Type": "application/json"}
    try:
        response = requests.post(url, headers=headers, json=pipeline_payload, timeout=20)
        response.raise_for_status()
        response_json = response.json()
        return jsonify({
            "name": pipeline_name,
            "pipelineIdentifier": pipeline_identifier,
            "projectId": project_id,
            "orgId": org_id,
            "accountId": HARNESS_ACCOUNT_ID,
            "harnessStatus": response_json.get("status")
        })
    except requests.RequestException as e:
        error_text = getattr(e.response, 'text', '') if getattr(e, 'response', None) else ""
        logger.error("Pipeline creation failed: %s", error_text)
        return jsonify({"error": f"Failed to create pipeline: {str(e)}", "response": error_text}), 400

# Run the app
if __name__ == "__main__":
    # Use debug=True for development; set False for production
    app.run(host="127.0.0.1", port=8000, debug=True)
