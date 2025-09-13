# Middleware for data validation and error handling
from flask import request, jsonify, current_app
from functools import wraps
import logging
import traceback
from datetime import datetime
import re

logger = logging.getLogger(__name__)

class ValidationError(Exception):
    """Custom validation error"""
    def __init__(self, message, field=None):
        self.message = message
        self.field = field
        super().__init__(self.message)

def validate_email(email):
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_coordinates(lat, lng):
    """Validate GPS coordinates"""
    try:
        lat_float = float(lat)
        lng_float = float(lng)
        return -90 <= lat_float <= 90 and -180 <= lng_float <= 180
    except (ValueError, TypeError):
        return False

def validate_required_fields(data, required_fields):
    """Validate that all required fields are present and not empty"""
    missing_fields = []
    for field in required_fields:
        if field not in data or not data[field] or str(data[field]).strip() == '':
            missing_fields.append(field)
    
    if missing_fields:
        raise ValidationError(f"Missing required fields: {', '.join(missing_fields)}")

def sanitize_input(data):
    """Sanitize input data to prevent XSS and injection attacks"""
    if isinstance(data, dict):
        return {key: sanitize_input(value) for key, value in data.items()}
    elif isinstance(data, list):
        return [sanitize_input(item) for item in data]
    elif isinstance(data, str):
        # Basic HTML tag removal and special character escaping
        data = re.sub(r'<[^>]*>', '', data)  # Remove HTML tags
        data = data.replace('<', '&lt;').replace('>', '&gt;')
        data = data.replace('"', '&quot;').replace("'", '&#x27;')
        return data.strip()
    else:
        return data

def error_handler(f):
    """Decorator for comprehensive error handling"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except ValidationError as e:
            logger.warning(f"Validation error in {f.__name__}: {e.message}")
            return jsonify({
                'error': 'Validation failed',
                'message': e.message,
                'field': e.field,
                'timestamp': datetime.utcnow().isoformat()
            }), 400
        except ValueError as e:
            logger.warning(f"Value error in {f.__name__}: {str(e)}")
            return jsonify({
                'error': 'Invalid data format',
                'message': str(e),
                'timestamp': datetime.utcnow().isoformat()
            }), 400
        except FileNotFoundError as e:
            logger.error(f"File not found in {f.__name__}: {str(e)}")
            return jsonify({
                'error': 'Resource not found',
                'message': 'The requested resource could not be found',
                'timestamp': datetime.utcnow().isoformat()
            }), 404
        except PermissionError as e:
            logger.error(f"Permission error in {f.__name__}: {str(e)}")
            return jsonify({
                'error': 'Access denied',
                'message': 'You do not have permission to access this resource',
                'timestamp': datetime.utcnow().isoformat()
            }), 403
        except Exception as e:
            logger.error(f"Unexpected error in {f.__name__}: {str(e)}")
            logger.error(traceback.format_exc())
            return jsonify({
                'error': 'Internal server error',
                'message': 'An unexpected error occurred',
                'timestamp': datetime.utcnow().isoformat(),
                'request_id': request.headers.get('X-Request-ID', 'unknown')
            }), 500
    return decorated_function

def validate_crack_data(f):
    """Decorator to validate crack report data"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method == 'POST':
            data = request.get_json() if request.is_json else request.form.to_dict()
            
            # Sanitize input data
            data = sanitize_input(data)
            
            # Validate coordinates if provided
            if 'latitude' in data and 'longitude' in data:
                if not validate_coordinates(data['latitude'], data['longitude']):
                    raise ValidationError("Invalid GPS coordinates", "coordinates")
            
            # Validate crack dimensions
            if 'length_mm' in data and data['length_mm']:
                try:
                    length = float(data['length_mm'])
                    if length <= 0 or length > 10000:  # Max 10 meters
                        raise ValidationError("Length must be between 0 and 10000mm", "length_mm")
                except ValueError:
                    raise ValidationError("Length must be a valid number", "length_mm")
            
            if 'width_mm' in data and data['width_mm']:
                try:
                    width = float(data['width_mm'])
                    if width <= 0 or width > 1000:  # Max 1 meter
                        raise ValidationError("Width must be between 0 and 1000mm", "width_mm")
                except ValueError:
                    raise ValidationError("Width must be a valid number", "width_mm")
            
            # Update request data with sanitized version
            if request.is_json:
                request.json = data
            
        return f(*args, **kwargs)
    return decorated_function

def validate_user_data(f):
    """Decorator to validate user registration/update data"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method == 'POST':
            data = request.get_json() if request.is_json else request.form.to_dict()
            
            # Sanitize input data
            data = sanitize_input(data)
            
            # Validate email format
            if 'email' in data:
                if not validate_email(data['email']):
                    raise ValidationError("Invalid email format", "email")
            
            # Validate password strength
            if 'password' in data:
                password = data['password']
                if len(password) < 8:
                    raise ValidationError("Password must be at least 8 characters long", "password")
                if not re.search(r'[A-Za-z]', password):
                    raise ValidationError("Password must contain at least one letter", "password")
                if not re.search(r'\d', password):
                    raise ValidationError("Password must contain at least one number", "password")
            
            # Validate name
            if 'name' in data:
                name = data['name']
                if len(name) < 2 or len(name) > 100:
                    raise ValidationError("Name must be between 2 and 100 characters", "name")
                if not re.match(r'^[a-zA-Z\s]+$', name):
                    raise ValidationError("Name can only contain letters and spaces", "name")
            
            # Update request data with sanitized version
            if request.is_json:
                request.json = data
            
        return f(*args, **kwargs)
    return decorated_function

def log_request():
    """Log incoming requests for monitoring"""
    @current_app.before_request
    def before_request():
        logger.info(f"{request.method} {request.path} - IP: {request.remote_addr}")
        
        # Add request ID for tracking
        if not hasattr(request, 'request_id'):
            request.request_id = datetime.utcnow().strftime('%Y%m%d%H%M%S') + str(hash(request.remote_addr))[:6]

def add_security_headers():
    """Add security headers to all responses"""
    @current_app.after_request
    def after_request(response):
        # Security headers
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        
        # CORS headers for API endpoints
        if request.path.startswith('/api/'):
            response.headers['Access-Control-Allow-Origin'] = '*'
            response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
            response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
        
        return response

def init_middleware(app):
    """Initialize all middleware"""
    log_request()
    add_security_headers()
    
    # Register error handlers
    @app.errorhandler(404)
    def not_found(error):
        if request.path.startswith('/api/'):
            return jsonify({
                'error': 'Not found',
                'message': 'The requested endpoint does not exist',
                'timestamp': datetime.utcnow().isoformat()
            }), 404
        return render_template('404.html'), 404
    
    @app.errorhandler(500)
    def internal_error(error):
        if request.path.startswith('/api/'):
            return jsonify({
                'error': 'Internal server error',
                'message': 'An unexpected error occurred',
                'timestamp': datetime.utcnow().isoformat()
            }), 500
        return render_template('500.html'), 500
