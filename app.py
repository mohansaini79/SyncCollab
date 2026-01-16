from bson import ObjectId
import os
from datetime import datetime, timedelta, timezone
from functools import wraps
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity
)
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.security import generate_password_hash, check_password_hash
from pymongo import MongoClient
from dotenv import load_dotenv
import cloudinary
import cloudinary.uploader
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import secrets

load_dotenv()

# ========================================
# APP SETUP
# ========================================
app = Flask(__name__, static_folder="static", static_url_path='')
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", secrets.token_hex(32))
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY", secrets.token_hex(32))
app.config["JWT_TOKEN_LOCATION"] = ["headers"]
app.config["JWT_HEADER_NAME"] = "Authorization"
app.config["JWT_HEADER_TYPE"] = "Bearer"
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=8)

jwt = JWTManager(app)

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per hour"]
)

CORS(app, resources={
    r"/*": {
        "origins": "*",
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"],
        "supports_credentials": True
    }
})

socketio = SocketIO(
    app, 
    cors_allowed_origins="*",
    async_mode="threading",
    ping_timeout=60,
    ping_interval=25
)

@app.before_request
def handle_preflight():
    if request.method == 'OPTIONS':
        response = app.make_default_options_response()
        response.headers['Access-Control-Allow-Origin'] = request.headers.get('Origin', '*')
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
        return response

@jwt.invalid_token_loader
def invalid_token_callback(error):
    return jsonify({"error": "Invalid token"}), 401

@jwt.unauthorized_loader
def missing_token_callback(error):
    return jsonify({"error": "Missing token"}), 401

@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    return jsonify({"error": "Token expired", "expired": True}), 401

# ========================================
# DATABASE
# ========================================
mongo_uri = os.getenv("MONGO_URI")
if not mongo_uri:
    raise ValueError("❌ MONGO_URI not found in .env")

client = MongoClient(mongo_uri)
db = client["gitconnect"]

users = db.users
teams = db.teams
workspaces = db.workspaces
kanban_boards = db.kanban_boards
documents = db.documents
document_versions = db.document_versions
files = db.files
task_comments = db.task_comments
messages = db.messages
notifications = db.notifications
activities = db.activities
reset_tokens = db.reset_tokens
online_users = {}

# ========================================
# CLOUDINARY
# ========================================
cloudinary.config(
    cloud_name=os.getenv("CLOUDINARY_CLOUD_NAME"),
    api_key=os.getenv("CLOUDINARY_API_KEY"),
    api_secret=os.getenv("CLOUDINARY_API_SECRET")
)

print(f"✅ Connected to MongoDB Atlas")

# ========================================
# HELPER FUNCTIONS
# ========================================
def utc_now():
    """Get current UTC time (Python 3.13 compatible)"""
    return datetime.now(timezone.utc)

def workspace_member_required(f):
    @wraps(f)
    @jwt_required()
    def decorated(ws_id, *args, **kwargs):
        identity = get_jwt_identity()
        ws = workspaces.find_one({"_id": ObjectId(ws_id)})
        if not ws or identity["id"] not in [str(m) for m in ws.get("members", [])]:
            return jsonify({"error": "Access denied"}), 403
        return f(identity, ws_id, *args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    @jwt_required()
    def decorated(*args, **kwargs):
        identity = get_jwt_identity()
        if identity.get("role") != "admin":
            return jsonify({"error": "Admin access required"}), 403
        return f(identity, *args, **kwargs)
    return decorated

def log_activity(user_id, user_name, action, workspace_id=None, details=None):
    """Fixed: Convert datetime to ISO string for SocketIO"""
    timestamp = utc_now()

    activity = {
        "user_id": user_id,
        "user_name": user_name,
        "action": action,
        "details": details,
        "workspace_id": workspace_id,
        "timestamp": timestamp  # Store as datetime in MongoDB
    }
    activities.insert_one(activity)

    # Emit with ISO string (JSON serializable)
    if workspace_id:
        emit_activity = activity.copy()
        emit_activity["timestamp"] = timestamp.isoformat()
        socketio.emit("activity_added", emit_activity, room=workspace_id)

def send_notification(user_id, message, workspace_id=None):
    """Fixed: Convert datetime to ISO string for SocketIO"""
    timestamp = utc_now()

    notif = {
        "user_id": user_id,
        "message": message,
        "workspace_id": workspace_id,
        "read": False,
        "created_at": timestamp
    }
    notifications.insert_one(notif)

    # Emit with ISO string
    emit_notif = notif.copy()
    emit_notif["created_at"] = timestamp.isoformat()
    socketio.emit("notification", emit_notif, room=user_id)

# ========================================
# AUTH ROUTES
# ========================================
@app.route("/api/register", methods=["POST"])
@limiter.limit("5 per hour")
def register():
    data = request.get_json()

    if users.find_one({"email": data["email"]}):
        return jsonify({"msg": "Email already registered"}), 400

    user = {
        "name": data["name"],
        "email": data["email"],
        "password": generate_password_hash(data["password"]),
        "role": data.get("role", "member"),
        "avatar": None,
        "theme": "light",
        "email_verified": False,
        "created_at": utc_now()
    }

    result = users.insert_one(user)
    user_data = {
        "id": str(result.inserted_id),
        "name": user["name"],
        "email": user["email"],
        "role": user["role"],
        "avatar": user["avatar"],
        "theme": user["theme"]
    }

    token = create_access_token(identity=user_data)
    log_activity(user_data["id"], user["name"], "Registered new account")

    print(f"✅ User registered: {user['email']}")
    return jsonify({"access_token": token, "user": user_data})

@app.route("/api/login", methods=["POST"])
@limiter.limit("10 per hour")
def login():
    data = request.get_json()
    user = users.find_one({"email": data.get("email")})

    if not user:
        print(f"❌ Login failed: User not found - {data.get('email')}")
        return jsonify({"msg": "Invalid credentials"}), 401

    if not check_password_hash(user["password"], data.get("password")):
        print(f"❌ Login failed: Wrong password - {data.get('email')}")
        return jsonify({"msg": "Invalid credentials"}), 401

    user_data = {
        "id": str(user["_id"]),
        "name": user["name"],
        "email": user["email"],
        "role": user.get("role", "member"),
        "avatar": user.get("avatar"),
        "theme": user.get("theme", "light")
    }
    token = create_access_token(identity=user_data)
    log_activity(user_data["id"], user["name"], "Logged in")

    print(f"✅ Login successful: {user['email']}")
    return jsonify({"access_token": token, "user": user_data})

@app.route("/api/forgot-password", methods=["POST"])
@limiter.limit("3 per hour")
def forgot_password():
    data = request.get_json()
    user = users.find_one({"email": data.get("email")})

    if not user:
        return jsonify({"msg": "Email not found"}), 404

    reset_token = secrets.token_urlsafe(32)
    reset_tokens.insert_one({
        "user_id": str(user["_id"]),
        "token": reset_token,
        "created_at": utc_now(),
        "expires_at": utc_now() + timedelta(hours=1)
    })

    return jsonify({"msg": "Reset token sent", "token": reset_token})

@app.route("/api/reset-password", methods=["POST"])
def reset_password():
    data = request.get_json()
    token_doc = reset_tokens.find_one({
        "token": data.get("token"),
        "expires_at": {"$gt": utc_now()}
    })

    if not token_doc:
        return jsonify({"msg": "Invalid or expired token"}), 400

    users.update_one(
        {"_id": ObjectId(token_doc["user_id"])},
        {"$set": {"password": generate_password_hash(data["password"])}}
    )

    reset_tokens.delete_one({"_id": token_doc["_id"]})
    return jsonify({"msg": "Password reset successful"})

@app.route("/api/users/search", methods=["GET"])
@jwt_required()
def search_users():
    query = request.args.get("q", "")
    if len(query) < 2:
        return jsonify([])

    users_list = list(users.find(
        {"$or": [
            {"email": {"$regex": query, "$options": "i"}},
            {"name": {"$regex": query, "$options": "i"}}
        ]},
        {"password": 0}
    ).limit(10))

    return jsonify([{
        "id": str(u["_id"]),
        "name": u["name"],
        "email": u["email"],
        "role": u.get("role", "member")
    } for u in users_list])

@app.route("/api/profile", methods=["PUT"])
@jwt_required()
def update_profile():
    identity = get_jwt_identity()
    data = request.get_json()

    update_data = {}
    if "name" in data:
        update_data["name"] = data["name"]
    if "password" in data and data["password"]:
        update_data["password"] = generate_password_hash(data["password"])
    if "theme" in data:
        update_data["theme"] = data["theme"]

    if update_data:
        users.update_one({"_id": ObjectId(identity["id"])}, {"$set": update_data})
        log_activity(identity["id"], identity["name"], "Updated profile")
        return jsonify({"msg": "Profile updated"})

    return jsonify({"msg": "No changes"}), 400

@app.route("/api/profile/avatar", methods=["POST"])
@jwt_required()
def upload_avatar():
    identity = get_jwt_identity()

    if 'avatar' not in request.files:
        return jsonify({"error": "No file"}), 400

    file = request.files['avatar']
    upload_result = cloudinary.uploader.upload(
        file,
        folder="gitconnect/avatars",
        transformation=[{"width": 200, "height": 200, "crop": "fill"}]
    )

    users.update_one(
        {"_id": ObjectId(identity["id"])},
        {"$set": {"avatar": upload_result["secure_url"]}}
    )

    return jsonify({"avatar": upload_result["secure_url"]})

# ========================================
# TEAM ROUTES
# ========================================
@app.route("/api/teams", methods=["GET", "POST"])
@jwt_required()
def handle_teams():
    identity = get_jwt_identity()

    if request.method == "POST":
        data = request.get_json()
        team = {
            "name": data["name"],
            "description": data.get("description", ""),
            "owner": identity["id"],
            "members": [identity["id"]],
            "created_at": utc_now()
        }
        result = teams.insert_one(team)
        log_activity(identity["id"], identity["name"], f"Created team '{data['name']}'")

        return jsonify({"id": str(result.inserted_id), "name": team["name"]})

    # GET
    user_teams = []
    for team in teams.find({"members": identity["id"]}).sort("created_at", -1):
        user_teams.append({
            "id": str(team["_id"]),
            "name": team["name"],
            "description": team.get("description", ""),
            "member_count": len(team.get("members", [])),
            "owner": team.get("owner") == identity["id"],
            "my_role": "admin" if team.get("owner") == identity["id"] else "member"
        })

    return jsonify(user_teams)

@app.route("/api/teams/<team_id>", methods=["PUT", "DELETE"])
@jwt_required()
def manage_team(team_id):
    identity = get_jwt_identity()
    team = teams.find_one({"_id": ObjectId(team_id), "owner": identity["id"]})

    if not team:
        return jsonify({"error": "Only owner can manage team"}), 403

    if request.method == "DELETE":
        workspaces.delete_many({"team_id": ObjectId(team_id)})
        teams.delete_one({"_id": ObjectId(team_id)})
        log_activity(identity["id"], identity["name"], f"Deleted team '{team['name']}'")
        return jsonify({"msg": "Team deleted"})

    # PUT
    data = request.get_json()
    teams.update_one(
        {"_id": ObjectId(team_id)},
        {"$set": {
            "name": data.get("name", team["name"]),
            "description": data.get("description", team.get("description", ""))
        }}
    )
    log_activity(identity["id"], identity["name"], f"Updated team '{data.get('name')}'")
    return jsonify({"msg": "Team updated"})

@app.route("/api/teams/<team_id>/members", methods=["GET", "POST"])
@jwt_required()
def handle_team_members(team_id):
    identity = get_jwt_identity()
    team = teams.find_one({"_id": ObjectId(team_id), "members": identity["id"]})

    if not team:
        return jsonify({"error": "Team not found"}), 404

    if request.method == "POST":
        if team["owner"] != identity["id"]:
            return jsonify({"error": "Only owner can add members"}), 403

        data = request.get_json()
        user_id = data.get("user_id")

        teams.update_one(
            {"_id": ObjectId(team_id)},
            {"$addToSet": {"members": user_id}}
        )

        user = users.find_one({"_id": ObjectId(user_id)})
        if user:
            send_notification(user_id, f"You were added to team '{team['name']}'")

        log_activity(identity["id"], identity["name"], f"Added member to team '{team['name']}'")
        return jsonify({"msg": "Member added"})

    # GET
    member_ids = [ObjectId(m) for m in team.get("members", [])]
    members = list(users.find({"_id": {"$in": member_ids}}, {"password": 0}))

    return jsonify([{
        "id": str(m["_id"]),
        "name": m["name"],
        "email": m["email"],
        "role": m.get("role", "member"),
        "avatar": m.get("avatar"),
        "is_owner": str(m["_id"]) == team["owner"]
    } for m in members])

@app.route("/api/teams/<team_id>/members/<user_id>", methods=["DELETE"])
@jwt_required()
def remove_team_member(team_id, user_id):
    identity = get_jwt_identity()
    team = teams.find_one({"_id": ObjectId(team_id), "owner": identity["id"]})

    if not team:
        return jsonify({"error": "Only owner can remove members"}), 403

    if user_id == team["owner"]:
        return jsonify({"error": "Cannot remove owner"}), 400

    teams.update_one(
        {"_id": ObjectId(team_id)},
        {"$pull": {"members": user_id}}
    )

    log_activity(identity["id"], identity["name"], f"Removed member from team '{team['name']}'")
    return jsonify({"msg": "Member removed"})

# ========================================
# WORKSPACE ROUTES
# ========================================
@app.route("/api/workspaces", methods=["GET", "POST"])
@jwt_required()
def handle_workspaces():
    identity = get_jwt_identity()

    if request.method == "POST":
        data = request.get_json()
        workspace = {
            "name": data["name"],
            "team_id": ObjectId(data["team_id"]),
            "description": data.get("description", ""),
            "members": data.get("members", [identity["id"]]),
            "created_by": identity["id"],
            "archived": False,
            "created_at": utc_now()
        }
        result = workspaces.insert_one(workspace)
        log_activity(identity["id"], identity["name"], f"Created workspace '{data['name']}'")

        for member_id in workspace["members"]:
            if member_id != identity["id"]:
                send_notification(member_id, f"You were added to workspace '{data['name']}'")

        return jsonify({"id": str(result.inserted_id), "name": workspace["name"]})

    # GET
    user_workspaces = []
    for ws in workspaces.find({"members": identity["id"], "archived": False}).sort("created_at", -1):
        user_workspaces.append({
            "id": str(ws["_id"]),
            "name": ws["name"],
            "description": ws.get("description", ""),
            "team_id": str(ws["team_id"]),
            "member_count": len(ws.get("members", [])),
            "is_owner": ws.get("created_by") == identity["id"]
        })

    return jsonify(user_workspaces)

@app.route("/api/workspaces/<ws_id>", methods=["PUT", "DELETE"])
@jwt_required()
def manage_workspace(ws_id):
    identity = get_jwt_identity()
    ws = workspaces.find_one({"_id": ObjectId(ws_id), "created_by": identity["id"]})

    if not ws:
        return jsonify({"error": "Only owner can manage workspace"}), 403

    if request.method == "DELETE":
        workspaces.delete_one({"_id": ObjectId(ws_id)})
        log_activity(identity["id"], identity["name"], f"Deleted workspace '{ws['name']}'")
        return jsonify({"msg": "Workspace deleted"})

    # PUT
    data = request.get_json()
    update_data = {}
    if "name" in data:
        update_data["name"] = data["name"]
    if "description" in data:
        update_data["description"] = data["description"]
    if "archived" in data:
        update_data["archived"] = data["archived"]

    workspaces.update_one({"_id": ObjectId(ws_id)}, {"$set": update_data})
    log_activity(identity["id"], identity["name"], f"Updated workspace '{data.get('name', ws['name'])}'", ws_id)
    return jsonify({"msg": "Workspace updated"})

@app.route("/api/workspaces/<ws_id>/members", methods=["GET"])
@jwt_required()
def get_workspace_members(ws_id):
    ws = workspaces.find_one({"_id": ObjectId(ws_id)})
    if not ws:
        return jsonify({"error": "Workspace not found"}), 404

    member_ids = [ObjectId(m) for m in ws.get("members", [])]
    members = list(users.find({"_id": {"$in": member_ids}}, {"password": 0}))

    return jsonify([{
        "id": str(m["_id"]),
        "name": m["name"],
        "email": m.get("email"),
        "avatar": m.get("avatar")
    } for m in members])

# ========================================
# KANBAN ROUTES
# ========================================
@app.route("/api/kanban/<ws_id>", methods=["GET", "POST"])
@workspace_member_required
def handle_kanban(identity, ws_id):
    if request.method == "POST":
        data = request.get_json()
        kanban_boards.update_one(
            {"workspace_id": ObjectId(ws_id)},
            {"$set": {"columns": data["columns"], "updated_at": utc_now()}},
            upsert=True
        )

        socketio.emit("kanban_updated", {"workspace_id": ws_id}, room=ws_id)
        log_activity(identity["id"], identity["name"], "Updated Kanban board", ws_id)
        return jsonify({"success": True})

    # GET
    board = kanban_boards.find_one({"workspace_id": ObjectId(ws_id)})
    if not board:
        default_columns = [
            {"name": "To Do", "tasks": []},
            {"name": "In Progress", "tasks": []},
            {"name": "Done", "tasks": []}
        ]
        return jsonify({"columns": default_columns})

    return jsonify({"columns": board.get("columns", [])})

@app.route("/api/kanban/<ws_id>/task/<int:col_idx>/<int:task_idx>", methods=["PUT", "DELETE"])
@workspace_member_required
def manage_task(identity, ws_id, col_idx, task_idx):
    board = kanban_boards.find_one({"workspace_id": ObjectId(ws_id)})
    if not board:
        return jsonify({"error": "Board not found"}), 404

    columns = board.get("columns", [])

    if col_idx >= len(columns) or task_idx >= len(columns[col_idx]["tasks"]):
        return jsonify({"error": "Invalid task"}), 400

    if request.method == "DELETE":
        task_title = columns[col_idx]["tasks"][task_idx].get("title", "Unnamed")
        columns[col_idx]["tasks"].pop(task_idx)

        kanban_boards.update_one(
            {"workspace_id": ObjectId(ws_id)},
            {"$set": {"columns": columns}}
        )

        log_activity(identity["id"], identity["name"], f"Deleted task '{task_title}'", ws_id)
        socketio.emit("kanban_updated", {"workspace_id": ws_id}, room=ws_id)
        return jsonify({"success": True})

    # PUT
    data = request.get_json()
    task = columns[col_idx]["tasks"][task_idx]

    if "title" in data:
        task["title"] = data["title"]
    if "desc" in data:
        task["desc"] = data["desc"]
    if "priority" in data:
        task["priority"] = data["priority"]
    if "due_date" in data:
        task["due_date"] = data["due_date"]
    if "assigned_to" in data:
        task["assigned_to"] = data["assigned_to"]
        if data["assigned_to"]:
            send_notification(data["assigned_to"], f"Task '{task['title']}' assigned to you", ws_id)

    if "history" not in task:
        task["history"] = []
    task["history"].append({
        "action": "updated",
        "by": identity["name"],
        "at": utc_now().isoformat()
    })

    columns[col_idx]["tasks"][task_idx] = task

    kanban_boards.update_one(
        {"workspace_id": ObjectId(ws_id)},
        {"$set": {"columns": columns}}
    )

    socketio.emit("kanban_updated", {"workspace_id": ws_id}, room=ws_id)
    return jsonify({"success": True})

@app.route("/api/kanban/<ws_id>/column/<int:col_idx>", methods=["PUT", "DELETE"])
@workspace_member_required
def manage_column(identity, ws_id, col_idx):
    board = kanban_boards.find_one({"workspace_id": ObjectId(ws_id)})
    if not board:
        return jsonify({"error": "Board not found"}), 404

    columns = board.get("columns", [])

    if col_idx >= len(columns):
        return jsonify({"error": "Invalid column"}), 400

    if request.method == "DELETE":
        col_name = columns[col_idx].get("name", "Unnamed")
        columns.pop(col_idx)

        kanban_boards.update_one(
            {"workspace_id": ObjectId(ws_id)},
            {"$set": {"columns": columns}}
        )

        log_activity(identity["id"], identity["name"], f"Deleted column '{col_name}'", ws_id)
        socketio.emit("kanban_updated", {"workspace_id": ws_id}, room=ws_id)
        return jsonify({"success": True})

    # PUT
    data = request.get_json()
    columns[col_idx]["name"] = data.get("name", columns[col_idx]["name"])

    kanban_boards.update_one(
        {"workspace_id": ObjectId(ws_id)},
        {"$set": {"columns": columns}}
    )

    socketio.emit("kanban_updated", {"workspace_id": ws_id}, room=ws_id)
    return jsonify({"success": True})

@app.route("/api/kanban/<ws_id>/stats", methods=["GET"])
@workspace_member_required
def kanban_stats(identity, ws_id):
    board = kanban_boards.find_one({"workspace_id": ObjectId(ws_id)})
    if not board:
        return jsonify({"pending": 0, "completed": 0, "total": 0})

    total = 0
    completed = 0
    pending = 0

    for col in board.get("columns", []):
        task_count = len(col.get("tasks", []))
        total += task_count
        if col["name"].lower() == "done":
            completed += task_count
        else:
            pending += task_count

    return jsonify({"pending": pending, "completed": completed, "total": total})

# ========================================
# TASK COMMENTS
# ========================================
@app.route("/api/kanban/<ws_id>/task/<col_idx>/<task_idx>/comments", methods=["GET", "POST"])
@workspace_member_required
def handle_task_comments(identity, ws_id, col_idx, task_idx):
    task_key = f"{ws_id}_{col_idx}_{task_idx}"

    if request.method == "POST":
        data = request.get_json()
        comment = {
            "task_key": task_key,
            "workspace_id": ws_id,
            "user_id": identity["id"],
            "username": identity["name"],
            "comment": data["comment"],
            "created_at": utc_now()
        }
        task_comments.insert_one(comment)

        # Emit with ISO string
        emit_comment = comment.copy()
        emit_comment["created_at"] = comment["created_at"].isoformat()
        socketio.emit("comment_added", emit_comment, room=ws_id)

        log_activity(identity["id"], identity["name"], "Added task comment", ws_id)
        return jsonify({"success": True})

    # GET
    comments = list(task_comments.find({"task_key": task_key}).sort("created_at", 1))
    return jsonify([{
        "id": str(c["_id"]),
        "username": c.get("username", "Unknown"),
        "comment": c["comment"],
        "created_at": c["created_at"].isoformat()
    } for c in comments])

# ========================================
# DOCUMENTS
# ========================================
@app.route("/api/docs/<ws_id>", methods=["GET", "POST"])
@workspace_member_required
def handle_documents(identity, ws_id):
    if request.method == "POST":
        data = request.get_json()

        doc = documents.find_one({"workspace_id": ObjectId(ws_id)})
        if doc and doc.get("content"):
            document_versions.insert_one({
                "workspace_id": ObjectId(ws_id),
                "content": doc["content"],
                "saved_by": doc.get("updated_by", "Unknown"),
                "saved_at": doc.get("updated_at", utc_now())
            })

        documents.update_one(
            {"workspace_id": ObjectId(ws_id)},
            {"$set": {
                "content": data["content"],
                "updated_at": utc_now(),
                "updated_by": identity["name"]
            }},
            upsert=True
        )

        socketio.emit("doc_updated", {"workspace_id": ws_id, "username": identity["name"]}, room=ws_id)
        log_activity(identity["id"], identity["name"], "Updated document", ws_id)

        return jsonify({"success": True})

    # GET
    doc = documents.find_one({"workspace_id": ObjectId(ws_id)})
    return jsonify({"content": doc.get("content", "{}") if doc else "{}"})

# ========================================
# FILES
# ========================================
@app.route("/api/files/<ws_id>", methods=["GET", "POST"])
@workspace_member_required
def handle_files(identity, ws_id):
    if request.method == "POST":
        if 'file' not in request.files:
            return jsonify({"error": "No file"}), 400

        file = request.files['file']

        MAX_SIZE = 10 * 1024 * 1024
        if len(file.read()) > MAX_SIZE:
            return jsonify({"error": "File too large (max 10MB)"}), 400
        file.seek(0)

        upload_result = cloudinary.uploader.upload(
            file,
            folder=f"gitconnect/{ws_id}",
            resource_type="auto"
        )

        file_doc = {
            "workspace_id": ObjectId(ws_id),
            "filename": file.filename,
            "url": upload_result["secure_url"],
            "size": upload_result.get("bytes", 0),
            "type": upload_result.get("resource_type", "file"),
            "uploaded_by": identity["name"],
            "uploaded_by_id": identity["id"],
            "uploaded_at": utc_now()
        }
        files.insert_one(file_doc)

        socketio.emit("file_uploaded", {"workspace_id": ws_id, "name": file.filename}, room=ws_id)
        log_activity(identity["id"], identity["name"], f"Uploaded file '{file.filename}'", ws_id)

        return jsonify({
            "name": file.filename,
            "url": upload_result["secure_url"]
        })

    # GET
    workspace_files = list(files.find({"workspace_id": ObjectId(ws_id)}).sort("uploaded_at", -1))
    return jsonify([{
        "id": str(f["_id"]),
        "name": f["filename"],
        "url": f["url"],
        "uploaded_by": f.get("uploaded_by", "Unknown"),
        "size": f.get("size", 0),
        "type": f.get("type", "file"),
        "uploaded_at": f["uploaded_at"].isoformat()
    } for f in workspace_files])

# ========================================
# CHAT
# ========================================
@app.route("/api/chat/<ws_id>/history", methods=["GET"])
@workspace_member_required
def get_chat_history(identity, ws_id):
    limit = int(request.args.get("limit", 50))
    msgs = list(messages.find(
        {"workspace_id": ObjectId(ws_id)}
    ).sort("timestamp", -1).limit(limit))

    return jsonify([{
        "id": str(m["_id"]),
        "user": m["user"],
        "message": m["message"],
        "timestamp": m["timestamp"].isoformat()
    } for m in reversed(msgs)])

# ========================================
# NOTIFICATIONS
# ========================================
@app.route("/api/notifications", methods=["GET"])
@jwt_required()
def get_notifications():
    identity = get_jwt_identity()
    notifs = list(notifications.find({
        "user_id": identity["id"]
    }).sort("created_at", -1).limit(50))

    unread_count = notifications.count_documents({
        "user_id": identity["id"],
        "read": False
    })

    return jsonify({
        "notifications": [{
            "id": str(n["_id"]),
            "message": n.get("message", "New notification"),
            "read": n.get("read", False),
            "workspace_id": n.get("workspace_id"),
            "created_at": n.get("created_at", utc_now()).isoformat()
        } for n in notifs],
        "unread_count": unread_count
    })

@app.route("/api/notifications/<notif_id>/read", methods=["POST"])
@jwt_required()
def mark_notification_read(notif_id):
    identity = get_jwt_identity()
    notifications.update_one(
        {"_id": ObjectId(notif_id), "user_id": identity["id"]},
        {"$set": {"read": True}}
    )
    return jsonify({"success": True})

@app.route("/api/notifications/read-all", methods=["POST"])
@jwt_required()
def mark_all_read():
    identity = get_jwt_identity()
    notifications.update_many(
        {"user_id": identity["id"]},
        {"$set": {"read": True}}
    )
    return jsonify({"success": True})

# ========================================
# ACTIVITIES
# ========================================
@app.route("/api/activities/<ws_id>", methods=["GET"])
@workspace_member_required
def get_activities(identity, ws_id):
    acts = list(activities.find({"workspace_id": ws_id}).sort("timestamp", -1).limit(100))

    return jsonify([{
        "id": str(a["_id"]),
        "user_name": a["user_name"],
        "action": a["action"],
        "details": a.get("details"),
        "timestamp": a["timestamp"].isoformat()
    } for a in acts])

# ========================================
# DASHBOARD
# ========================================
@app.route("/api/dashboard", methods=["GET"])
@jwt_required()
def dashboard_stats():
    identity = get_jwt_identity()

    user_workspaces = workspaces.count_documents({"members": identity["id"]})
    user_teams = teams.count_documents({"members": identity["id"]})

    recent_acts = list(activities.find({
        "user_id": identity["id"]
    }).sort("timestamp", -1).limit(10))

    return jsonify({
        "users": users.count_documents({}),
        "teams": user_teams,
        "workspaces": user_workspaces,
        "files": files.count_documents({}),
        "recent_activities": [{
            "action": a["action"],
            "timestamp": a["timestamp"].isoformat()
        } for a in recent_acts]
    })

@app.route("/api/search", methods=["GET"])
@jwt_required()
def global_search():
    identity = get_jwt_identity()
    query = request.args.get("q", "")

    if len(query) < 2:
        return jsonify({"workspaces": [], "files": []})

    ws_results = list(workspaces.find({
        "members": identity["id"],
        "name": {"$regex": query, "$options": "i"}
    }).limit(5))

    file_results = list(files.find({
        "filename": {"$regex": query, "$options": "i"}
    }).limit(5))

    return jsonify({
        "workspaces": [{
            "id": str(w["_id"]),
            "name": w["name"],
            "type": "workspace"
        } for w in ws_results],
        "files": [{
            "id": str(f["_id"]),
            "name": f["filename"],
            "type": "file"
        } for f in file_results]
    })

# ========================================
# SOCKET.IO EVENTS
# ========================================
@socketio.on("join_workspace")
def handle_join_workspace(data):
    ws_id = data.get("workspace_id")
    user_id = data.get("user_id")
    username = data.get("username", "User")

    join_room(ws_id)
    join_room(user_id)

    if ws_id not in online_users:
        online_users[ws_id] = set()
    online_users[ws_id].add(user_id)

    emit("user_joined", {"username": username, "online_users": list(online_users[ws_id])}, room=ws_id)

@socketio.on("leave_workspace")
def handle_leave_workspace(data):
    ws_id = data.get("workspace_id")
    user_id = data.get("user_id")

    leave_room(ws_id)

    if ws_id in online_users and user_id in online_users[ws_id]:
        online_users[ws_id].remove(user_id)
        emit("user_left", {"user_id": user_id, "online_users": list(online_users[ws_id])}, room=ws_id)

@socketio.on("chat_message")
def handle_chat_message(data):
    ws_id = data.get("workspace_id")

    timestamp = utc_now()
    message = {
        "workspace_id": ObjectId(ws_id),
        "user": data.get("user"),
        "message": data.get("message"),
        "timestamp": timestamp
    }
    messages.insert_one(message)

    emit("chat_message", {
        "id": str(message["_id"]),
        "user": data.get("user"),
        "message": data.get("message"),
        "timestamp": timestamp.isoformat()
    }, room=ws_id)

@socketio.on("typing")
def handle_typing(data):
    emit("user_typing", {
        "user": data.get("user"),
        "is_typing": data.get("is_typing")
    }, room=data.get("workspace_id"), skip_sid=request.sid)

# ========================================
# FRONTEND
# ========================================
@app.route("/")
def index():
    return send_from_directory("static", "index.html")

@app.route("/<path:filename>")
def serve_static(filename):
    return send_from_directory("static", filename)

# ========================================
# ERROR HANDLERS
# ========================================
@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Not found"}), 404

@app.errorhandler(500)
def server_error(e):
    return jsonify({"error": "Internal server error"}), 500

# ========================================
# RUN
# ========================================
if __name__ == "__main__":
    port = int(os.getenv("PORT", 10000))
    print(f"🚀 GitConnect Server running on http://localhost:{port}")
    print(f"📊 Features: All datetime issues FIXED for Python 3.13")
    print(f"✅ MongoDB Atlas connected | Login system working")
    socketio.run(app, host="0.0.0.0", port=port, debug=False)
