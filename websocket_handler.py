# Real-time WebSocket Handler for FixZen
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask import request
import jwt
import logging
import json
from datetime import datetime

logger = logging.getLogger(__name__)

def init_socketio(app):
    """Initialize WebSocket support"""
    socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')
    
    @socketio.on('connect')
    def handle_connect():
        """Handle client connection"""
        try:
            token = request.args.get('token')
            if token:
                data = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
                user_id = data['user_id']
                join_room(f'user_{user_id}')
                emit('status', {'message': 'Connected successfully'})
                logger.info(f"User {user_id} connected via WebSocket")
            else:
                emit('error', {'message': 'Authentication required'})
        except jwt.InvalidTokenError:
            emit('error', {'message': 'Invalid token'})
        except Exception as e:
            logger.error(f"WebSocket connection error: {str(e)}")
            emit('error', {'message': 'Connection failed'})
    
    @socketio.on('disconnect')
    def handle_disconnect():
        """Handle client disconnection"""
        logger.info("Client disconnected from WebSocket")
    
    @socketio.on('join_notifications')
    def handle_join_notifications(data):
        """Join notification room for real-time updates"""
        try:
            user_id = data.get('user_id')
            if user_id:
                join_room(f'notifications_{user_id}')
                emit('status', {'message': 'Joined notification room'})
        except Exception as e:
            logger.error(f"Join notifications error: {str(e)}")
    
    @socketio.on('crack_analysis_status')
    def handle_crack_status(data):
        """Request crack analysis status"""
        try:
            crack_id = data.get('crack_id')
            if crack_id:
                # Emit current status
                emit('crack_status_update', {
                    'crack_id': crack_id,
                    'status': 'processing',
                    'progress': 75,
                    'message': 'AI analysis in progress...'
                })
        except Exception as e:
            logger.error(f"Crack status error: {str(e)}")
    
    def send_notification(user_id, notification_data):
        """Send real-time notification to user"""
        try:
            socketio.emit('new_notification', notification_data, room=f'notifications_{user_id}')
            logger.info(f"Sent notification to user {user_id}")
        except Exception as e:
            logger.error(f"Send notification error: {str(e)}")
    
    def broadcast_crack_update(crack_id, status_data):
        """Broadcast crack analysis update"""
        try:
            socketio.emit('crack_analysis_complete', {
                'crack_id': crack_id,
                'timestamp': datetime.utcnow().isoformat(),
                **status_data
            }, broadcast=True)
        except Exception as e:
            logger.error(f"Broadcast crack update error: {str(e)}")
    
    # Attach helper functions to socketio instance
    socketio.send_notification = send_notification
    socketio.broadcast_crack_update = broadcast_crack_update
    
    return socketio
