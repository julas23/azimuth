from flask import Flask, jsonify, request
from flask_cors import CORS
from api_routes import api

app = Flask(__name__)
CORS(app)  # Enable CORS for frontend communication

# Register API blueprint
app.register_blueprint(api)

@app.route("/")
def index():
    return jsonify({
        "message": "Home Server Admin Backend",
        "version": "1.0.0",
        "endpoints": {
            "services": "/api/v1/services/<service_name>",
            "network": "/api/v1/network/interfaces",
            "nftables": "/api/v1/nftables/ruleset",
            "wireguard": "/api/v1/wireguard/status",
            "fail2ban": "/api/v1/fail2ban/status"
        }
    })

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
