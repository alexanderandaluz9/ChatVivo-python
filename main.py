# Importación de Librerias
# Librerias para la API y la autenticación
from flask import Flask, render_template, redirect, request, flash, url_for, abort, current_app
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

import logging
import os

# Librerias para el Chat
from flask_socketio import SocketIO, emit, join_room, leave_room
import secrets

import hashlib
sha256_hash = hashlib.sha256()


# Comienzo de la API
app= Flask(__name__)
 

# Congiguración Relacionada con la authenticación
logging.basicConfig(level=logging.DEBUG)

#Función control estado
def estado(mensaje, categoria="info"):
    if categoria == "danger":
        app.logger.error(mensaje)
    elif categoria == "warning":
        app.logger.warning(mensaje)
    elif categoria == "success":
        app.logger.info(mensaje)
    else:
        app.logger.debug(mensaje)
    
    flash(mensaje, categoria)



# Creación del archivo db
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.session_protection = "strong"
socketio = SocketIO(app)
app.config['SECRET_KEY'] = secrets.token_hex(16)
app.config['SESSION_COOKIE_NAME'] = 'chat_session'
app.config['UPLOAD_FOLDER'] = 'static/avatars'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}

# Avatares
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# Función para verificar extensiones permitidas
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']



# Ajuste del db
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(25), nullable=False, unique=True)
    password = db.Column(db.String(100), nullable=False)
    name = db.Column(db.String(25), nullable=False)
    avatar = db.Column(db.String(100))

@login_manager.user_loader
def cargar_usuario(user_id):
    app.logger.debug(f"Intentando cargar usuario con ID: {user_id}")
    usuario = User.query.get(int(user_id))
    if usuario:
        app.logger.debug(f"Usuario cargado: {usuario.username}")
    else:
        estado('No se encontró el usuario', 'warning')
    return usuario

@login_manager.unauthorized_handler
def unauthorized():
    app.logger.debug(f"Intento de acceso no autorizado")
    estado('Por favor, inicia sesión para acceder a esta página', 'warning')
    return redirect(url_for('login'))


#endpoint Registro
@app.route('/registro', methods=['GET', 'POST'])
def registro():
    try:
        if request.method == "POST":
            username = request.form['username']
            password = request.form['password']
            name = request.form['name']

            app.logger.debug(f"Intento de registro para usuario: {username}")

            if User.query.filter_by(username=username).first():
                estado('El nombre de usuario ya existe', 'danger')
                return redirect(url_for('registro'))

            hashed_password = generate_password_hash(password, method="pbkdf2:sha256", salt_length=16)
            new_user = User(username=username, password=hashed_password, name=name)
            db.session.add(new_user)
            db.session.commit()

            estado('Registro exitoso', 'success')
            return redirect(url_for('login'))
        return render_template('registro.html')
    except Exception as e:
        estado(f"Error en el registro: {str(e)}", 'danger')
        return render_template('registro.html')
    
#Endpoint Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    try:
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']

            app.logger.debug(f"Intento de inicio de sesión para usuario: {username}")

            user = User.query.filter_by(username=username).first()
            if user and check_password_hash(user.password, password):
                login_user(user)
                estado('Inicio de sesión exitoso', 'success')
                return redirect(url_for('chat'))
            else:
                estado('Nombre de usuario o contraseña incorrectos', 'danger')
        return render_template('login.html')
    except Exception as e:
        estado(f"Error en el inicio de sesión: {str(e)}", 'danger')
        return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    username = current_user.username
    logout_user()
    app.logger.debug(f"Usuario {username} ha cerrado sesión")
    estado('Has cerrado sesión', 'success')
    return redirect(url_for('login'))


# Dashboard
@app.route('/dashboard')
@login_required
def dashboard():
    app.logger.debug(f"Acceso al dashboard por usuario: {current_user.username}")
    return render_template('dashboard.html')


@app.route('/update_avatar', methods=['POST'])
@login_required
def update_avatar():
    try:
        if 'avatar' not in request.files:
            estado('No se seleccionó ningún archivo', 'warning')
            return redirect(url_for('dashboard'))
        
        file = request.files['avatar']
        
        if file.filename == '':
            estado('No se seleccionó ningún archivo', 'warning')
            return redirect(url_for('dashboard'))
        
        if file and allowed_file(file.filename):
            # Borrar avatar anterior si existe
            if current_user.avatar:
                try:
                    old_avatar_path = os.path.join(app.config['UPLOAD_FOLDER'], current_user.avatar)
                    if os.path.exists(old_avatar_path):
                        os.remove(old_avatar_path)
                except Exception as e:
                    app.logger.error(f"Error eliminando avatar anterior: {str(e)}")
            
            # Guardar nuevo avatar
            filename = secure_filename(f"user_{current_user.id}_{file.filename}")
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            
            # Actualizar la información del usuario
            current_user.avatar = filename
            db.session.commit()
            
            estado('Avatar actualizado correctamente', 'success')
        else:
            estado('Formato de archivo no permitido', 'danger')
        
        return redirect(url_for('dashboard'))
    except Exception as e:
        estado(f"Error al actualizar el avatar: {str(e)}", 'danger')
        return redirect(url_for('dashboard'))


# Endpoint para actualizar el perfil
@app.route('/update_profile', methods=['POST'])
@login_required
def update_profile():
    try:
        name = request.form['name']
        username = request.form['username']
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        
        # Verificar contraseña actual
        if not check_password_hash(current_user.password, current_password):
            estado('La contraseña actual es incorrecta', 'danger')
            return redirect(url_for('dashboard'))
        
        # Verificar si el nuevo nombre de usuario ya existe (si es diferente al actual)
        if username != current_user.username:
            if User.query.filter_by(username=username).first():
                estado('El nombre de usuario ya está en uso', 'danger')
                return redirect(url_for('dashboard'))
        
        # Actualizar nombre y nombre de usuario
        current_user.name = name
        current_user.username = username
        
        # Actualizar contraseña si se proporcionó una nueva
        if new_password:
            if new_password != confirm_password:
                estado('Las contraseñas no coinciden', 'danger')
                return redirect(url_for('dashboard'))
            
            hashed_password = generate_password_hash(new_password, method="pbkdf2:sha256")
            current_user.password = hashed_password
        
        # Guardar cambios
        db.session.commit()
        estado('Perfil actualizado correctamente', 'success')
        
        return redirect(url_for('dashboard'))
    except Exception as e:
        estado(f"Error al actualizar el perfil: {str(e)}", 'danger')
        return redirect(url_for('dashboard'))





# Errores
@app.errorhandler(404)
def page_not_found(e):
    estado('Página no encontrada', 'warning')
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    estado('Error interno del servidor', 'danger')
    return render_template('500.html'), 500

# Confguración del Chat
usuarios = {}  # Diccionario para almacenar usuarios conectados

@app.route('/chat')
@login_required
def chat():
    app.logger.debug(f"Acceso al chat por usuario: {current_user.username}")
    return render_template('chat.html')


@socketio.on('conectar')
def manejar_conexion(data):
    session_id = request.sid
    username = current_user.username
    user_id = current_user.id


    usuarios[session_id] = {
        'username': username,
        'id': user_id,
        'name': current_user.name,
        'avatar': current_user.avatar
    }


    app.logger.debug(f"Usuario {username} conectado con ID de sesión: {session_id}")

    join_room('general')

    # Emitir mensaje de nueva conexión
    emit('mensaje_sistema', {
        'username': 'Sistema',
        'mensaje': f'{username} se ha unido al chat'
    }, room='general')
    emit('lista_usuarios', list(usuarios.values()), room='general', broadcast=True)

@socketio.on('ping')
def handle_ping():
    session_id = request.sid
    if session_id in usuarios:
        emit('pong', {'status': 'connected'})
        app.logger.debug(f"Ping recibido de {usuarios[session_id]['username']}")
    else:
        # Reconectar al usuario si no está en la lista
        manejar_conexion({})

@socketio.on('enviar_mensaje')
def manejar_mensaje(data):
    session_id = request.sid
    usuario = usuarios.get(session_id, {'username': 'Anónimo'})

    app.logger.debug(f"Mensaje enviado por {usuario['username']}: {data['mensaje']}")

    emit('nuevo_mensaje', {
        'username': usuario['username'], 
        'mensaje': data['mensaje']
    }, room='general')

@socketio.on('disconnect')
def manejar_desconexion():
    session_id = request.sid
    usuario = usuarios.pop(session_id, None)

    if usuario:
        app.logger.debug(f"Usuario {usuario['username']} desconectado")

        emit('mensaje_sistema', {
            'username': 'Sistema', 
            'mensaje': f'{usuario["username"]} ha abandonado el chat'
        }, room='general')

        emit('lista_usuarios', list(usuarios.values()), room='general')


# Fin de la configuración API
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)