from flask import Flask, render_template, request, session
from flask_socketio import SocketIO, emit, join_room
from googletrans import Translator
import eventlet
import os

# Monkey patching for eventlet
eventlet.monkey_patch()

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Secure session key
socketio = SocketIO(app, async_mode='eventlet')  # Enable Socket.IO

translator = Translator()  # Initialize Translator

@app.route('/')
def home():
    return render_template('login.html')

@app.route('/chat', methods=['GET'])
def chat_room():
    username = request.args.get('username')
    language = request.args.get('language')
    room = request.args.get('room', 'default')  # Default room

    if not username or not language:
        return "Missing username or language", 400

    session['username'] = username
    session['language'] = language
    session['room'] = room

    return render_template('chat.html', username=username, room=room)

@socketio.on('connect')
def handle_connect():
    username = session.get('username')
    room = session.get('room')
    if username and room:
        join_room(room)
        emit('user_connected', {'username': username}, room=room, broadcast=True)

@socketio.on('send_message')
def handle_send_message(data):
    username = session.get('username')
    user_language = session.get('language')
    room = session.get('room')
    message = data.get('message', '')

    if not username or not message:
        return

    try:
        translated_message = translator.translate(message, dest=user_language).text
    except Exception:
        translated_message = message  # In case translation fails, send original message

    emit('receive_message', {'username': username, 'message': translated_message}, room=room)

@socketio.on('disconnect')
def handle_disconnect():
    username = session.get('username')
    room = session.get('room')
    if username and room:
        emit('user_disconnected', {'username': username}, room=room, broadcast=True)

if __name__ == '__main__':
    socketio.run(app, host='127.0.0.1', port=8000, debug=True)
