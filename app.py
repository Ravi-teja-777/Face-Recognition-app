from flask import Flask, request, jsonify, session, render_template, redirect, url_for, flash
from werkzeug.utils import secure_filename
import boto3
from botocore.exceptions import ClientError
import uuid
import os
from datetime import datetime
from decimal import Decimal
import traceback

app = Flask(__name__)
app.config['SECRET_KEY'] = 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# AWS Configuration
AWS_REGION = 'us-east-1'
BUCKET_NAME = "face-auth-storage-bucket"
COLLECTION_ID = "my-face-collection"
USERS_TABLE = "face-users"
LOGS_TABLE = "face-logs"

# AWS clients
s3 = boto3.client('s3', region_name=AWS_REGION)
rekognition = boto3.client('rekognition', region_name=AWS_REGION)
dynamodb = boto3.resource('dynamodb', region_name=AWS_REGION)
users_table = dynamodb.Table(USERS_TABLE)
logs_table = dynamodb.Table(LOGS_TABLE)

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def log_activity(user_id, username, action, status):
    """Log user activity to DynamoDB"""
    try:
        logs_table.put_item(
            Item={
                'log_id': str(uuid.uuid4()),
                'user_id': user_id,
                'username': username,
                'action': action,
                'status': status,
                'timestamp': datetime.now().isoformat()
            }
        )
    except Exception as e:
        print(f"Logging error: {str(e)}")

def login_required(f):
    """Decorator to protect routes"""
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('Please login first', 'error')
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return decorated_function

def init_aws_resources():
    """Initialize all AWS resources"""
    print("\n" + "="*60)
    print("Initializing AWS Resources...")
    print("="*60)
    
    try:
        # 1. Create S3 bucket
        try:
            s3.head_bucket(Bucket=BUCKET_NAME)
            print(f"✓ S3 bucket '{BUCKET_NAME}' exists")
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == '404':
                try:
                    # For us-east-1, don't specify LocationConstraint
                    if AWS_REGION == 'us-east-1':
                        s3.create_bucket(Bucket=BUCKET_NAME)
                    else:
                        s3.create_bucket(
                            Bucket=BUCKET_NAME,
                            CreateBucketConfiguration={'LocationConstraint': AWS_REGION}
                        )
                    print(f"✓ Created S3 bucket '{BUCKET_NAME}'")
                except ClientError as create_error:
                    print(f"✗ Failed to create S3 bucket: {str(create_error)}")
            else:
                print(f"✗ S3 bucket check failed: {str(e)}")
        
        # 2. Create Rekognition collection
        try:
            rekognition.describe_collection(CollectionId=COLLECTION_ID)
            print(f"✓ Rekognition collection '{COLLECTION_ID}' exists")
        except rekognition.exceptions.ResourceNotFoundException:
            try:
                rekognition.create_collection(CollectionId=COLLECTION_ID)
                print(f"✓ Created Rekognition collection '{COLLECTION_ID}'")
            except Exception as create_error:
                print(f"✗ Failed to create Rekognition collection: {str(create_error)}")
        except Exception as e:
            print(f"✗ Rekognition collection check failed: {str(e)}")
        
        # 3. Check DynamoDB tables
        try:
            users_table.load()
            print(f"✓ DynamoDB table '{USERS_TABLE}' exists")
        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceNotFoundException':
                print(f"✗ DynamoDB table '{USERS_TABLE}' does NOT exist")
                print(f"   Please create it manually with:")
                print(f"   - Partition key: username (String)")
            else:
                print(f"✗ Error checking users table: {str(e)}")
        
        try:
            logs_table.load()
            print(f"✓ DynamoDB table '{LOGS_TABLE}' exists")
        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceNotFoundException':
                print(f"✗ DynamoDB table '{LOGS_TABLE}' does NOT exist")
                print(f"   Please create it manually with:")
                print(f"   - Partition key: log_id (String)")
            else:
                print(f"✗ Error checking logs table: {str(e)}")
        
        print("="*60)
        print("AWS Resource Initialization Complete")
        print("="*60 + "\n")
            
    except Exception as e:
        print(f"\n✗ AWS initialization error: {str(e)}")
        print(traceback.format_exc())
        print("="*60 + "\n")

# ==================== HTML PAGE ROUTES ====================

@app.route('/')
def home():
    """Home page - Landing page"""
    return render_template('home.html')

@app.route('/login')
def login_page():
    """Login page - Face recognition login"""
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/register')
def register_page():
    """Register page - New user registration"""
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return render_template('register.html')

@app.route('/dashboard')
@login_required
def dashboard():
    """Dashboard - Analytics page after login"""
    try:
        username = session['username']
        
        # Get user data
        response = users_table.get_item(Key={'username': username})
        user = response.get('Item', {})
        
        # Get recent logs
        logs_response = logs_table.scan(
            FilterExpression='username = :uname',
            ExpressionAttributeValues={':uname': username},
            Limit=20
        )
        
        # Get all users count
        all_users = users_table.scan(Select='COUNT')
        
        analytics_data = {
            'username': username,
            'user_id': user.get('user_id'),
            'login_count': user.get('login_count', 0),
            'created_at': user.get('created_at'),
            'total_users': all_users['Count'],
            'recent_activity': logs_response.get('Items', [])[:10]
        }
        
        return render_template('dashboard.html', data=analytics_data)
        
    except Exception as e:
        flash(f'Error loading dashboard: {str(e)}', 'error')
        return redirect(url_for('home'))

@app.route('/create-user-page')
@login_required
def create_user_page():
    """Admin page to create new users"""
    return render_template('create_user.html', admin_username=session['username'])

@app.route('/profile')
@login_required
def profile():
    """User profile page"""
    try:
        username = session['username']
        response = users_table.get_item(Key={'username': username})
        user = response.get('Item', {})
        
        return render_template('profile.html', user=user)
        
    except Exception as e:
        flash(f'Error loading profile: {str(e)}', 'error')
        return redirect(url_for('dashboard'))

# ==================== API ROUTES ====================

@app.route('/api/register', methods=['POST'])
def api_register():
    """API: Register new user with face image"""
    try:
        print("\n[REGISTER] Starting registration process...")
        
        if 'image' not in request.files:
            print("[REGISTER] Error: No image in request")
            return jsonify({'error': 'No image provided'}), 400
        
        if 'username' not in request.form:
            print("[REGISTER] Error: No username in request")
            return jsonify({'error': 'Username required'}), 400
        
        file = request.files['image']
        username = request.form['username']
        
        print(f"[REGISTER] Username: {username}, File: {file.filename}")
        
        if file.filename == '':
            return jsonify({'error': 'No selected file'}), 400
        
        if not allowed_file(file.filename):
            return jsonify({'error': 'Invalid file type. Use PNG, JPG, or JPEG'}), 400
        
        # Check if user already exists
        print(f"[REGISTER] Checking if user exists...")
        response = users_table.get_item(Key={'username': username})
        if 'Item' in response:
            print(f"[REGISTER] Error: User already exists")
            return jsonify({'error': 'Username already exists'}), 400
        
        # Read image
        image_bytes = file.read()
        print(f"[REGISTER] Image size: {len(image_bytes)} bytes")
        
        # Generate unique user ID and filename
        user_id = str(uuid.uuid4())
        filename = f"users/{user_id}/{secure_filename(file.filename)}"
        
        print(f"[REGISTER] Uploading to S3: {filename}")
        # Upload to S3
        s3.put_object(
            Bucket=BUCKET_NAME,
            Key=filename,
            Body=image_bytes,
            ContentType=file.content_type
        )
        print(f"[REGISTER] S3 upload successful")
        
        print(f"[REGISTER] Indexing face in Rekognition...")
        # Index face in Rekognition - FIXED: Use username as ExternalImageId
        response = rekognition.index_faces(
            CollectionId=COLLECTION_ID,
            Image={'S3Object': {'Bucket': BUCKET_NAME, 'Name': filename}},
            ExternalImageId=username,  # CHANGED: Use username instead of user_id
            DetectionAttributes=['ALL']
        )
        
        if not response['FaceRecords']:
            print(f"[REGISTER] Error: No face detected")
            return jsonify({'error': 'No face detected in image'}), 400
        
        face_id = response['FaceRecords'][0]['Face']['FaceId']
        print(f"[REGISTER] Face indexed successfully. Face ID: {face_id}")
        
        print(f"[REGISTER] Storing user in DynamoDB...")
        # Store user in DynamoDB
        users_table.put_item(
            Item={
                'username': username,
                'user_id': user_id,
                'face_id': face_id,
                's3_key': filename,
                'created_at': datetime.now().isoformat(),
                'login_count': 0
            }
        )
        print(f"[REGISTER] User stored successfully")
        
        log_activity(user_id, username, 'register', 'success')
        
        print(f"[REGISTER] Registration complete for user: {username}")
        return jsonify({
            'success': True,
            'message': 'Registration successful',
            'redirect': url_for('login_page')
        }), 201
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        error_message = e.response['Error']['Message']
        print(f"[REGISTER] AWS Error: {error_code} - {error_message}")
        print(traceback.format_exc())
        return jsonify({'error': f'AWS Error: {error_message}'}), 500
    except Exception as e:
        print(f"[REGISTER] Error: {str(e)}")
        print(traceback.format_exc())
        return jsonify({'error': f'Registration failed: {str(e)}'}), 500

@app.route('/api/login', methods=['POST'])
def api_login():
    """API: Login user with face recognition"""
    try:
        print("\n[LOGIN] Starting login process...")
        
        if 'image' not in request.files:
            print("[LOGIN] Error: No image in request")
            return jsonify({'error': 'No image provided'}), 400
        
        file = request.files['image']
        
        if file.filename == '':
            return jsonify({'error': 'No selected file'}), 400
        
        if not allowed_file(file.filename):
            return jsonify({'error': 'Invalid file type'}), 400
        
        image_bytes = file.read()
        print(f"[LOGIN] Image size: {len(image_bytes)} bytes")
        
        print(f"[LOGIN] Searching for face in Rekognition...")
        # Search for face in collection
        response = rekognition.search_faces_by_image(
            CollectionId=COLLECTION_ID,
            Image={'Bytes': image_bytes},
            MaxFaces=1,
            FaceMatchThreshold=80
        )
        
        if not response['FaceMatches']:
            print(f"[LOGIN] No matching face found")
            log_activity('unknown', 'unknown', 'login', 'failed - no match')
            return jsonify({'error': 'Face not recognized. Please try again or register.'}), 401
        
        # Get matched face
        match = response['FaceMatches'][0]
        username = match['Face']['ExternalImageId']  # CHANGED: This is now username
        confidence = match['Similarity']
        
        print(f"[LOGIN] Face matched! Username: {username}, Confidence: {confidence}%")
        
        # Get user from DynamoDB - FIXED: Direct lookup by username
        response = users_table.get_item(Key={'username': username})
        
        if 'Item' not in response:
            print(f"[LOGIN] Error: User not found in database")
            return jsonify({'error': 'User not found'}), 404
        
        user = response['Item']
        print(f"[LOGIN] User found: {user['username']}")
        
        # Update login count
        users_table.update_item(
            Key={'username': user['username']},
            UpdateExpression='SET login_count = login_count + :inc',
            ExpressionAttributeValues={':inc': 1}
        )
        
        # Set session
        session['user_id'] = user['user_id']
        session['username'] = user['username']
        
        log_activity(user['user_id'], user['username'], 'login', 'success')
        
        print(f"[LOGIN] Login successful for user: {user['username']}")
        return jsonify({
            'success': True,
            'message': 'Login successful',
            'username': user['username'],
            'confidence': float(confidence),
            'redirect': url_for('dashboard')
        }), 200
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        error_message = e.response['Error']['Message']
        print(f"[LOGIN] AWS Error: {error_code} - {error_message}")
        print(traceback.format_exc())
        return jsonify({'error': f'AWS Error: {error_message}'}), 500
    except Exception as e:
        print(f"[LOGIN] Error: {str(e)}")
        print(traceback.format_exc())
        return jsonify({'error': f'Login failed: {str(e)}'}), 500

@app.route('/api/create-user', methods=['POST'])
@login_required
def api_create_user():
    """API: Admin endpoint to create new user"""
    try:
        print("\n[CREATE USER] Starting user creation...")
        
        if 'image' not in request.files:
            return jsonify({'error': 'No image provided'}), 400
        
        if 'username' not in request.form:
            return jsonify({'error': 'Username required'}), 400
        
        file = request.files['image']
        new_username = request.form['username']
        
        print(f"[CREATE USER] New username: {new_username}")
        
        if not allowed_file(file.filename):
            return jsonify({'error': 'Invalid file type'}), 400
        
        # Check if user exists
        response = users_table.get_item(Key={'username': new_username})
        if 'Item' in response:
            return jsonify({'error': 'Username already exists'}), 400
        
        image_bytes = file.read()
        user_id = str(uuid.uuid4())
        filename = f"users/{user_id}/{secure_filename(file.filename)}"
        
        # Upload to S3
        s3.put_object(
            Bucket=BUCKET_NAME,
            Key=filename,
            Body=image_bytes,
            ContentType=file.content_type
        )
        
        # Index face - FIXED: Use username as ExternalImageId
        response = rekognition.index_faces(
            CollectionId=COLLECTION_ID,
            Image={'S3Object': {'Bucket': BUCKET_NAME, 'Name': filename}},
            ExternalImageId=new_username,  # CHANGED: Use username instead of user_id
            DetectionAttributes=['ALL']
        )
        
        if not response['FaceRecords']:
            return jsonify({'error': 'No face detected'}), 400
        
        face_id = response['FaceRecords'][0]['Face']['FaceId']
        
        # Store user
        users_table.put_item(
            Item={
                'username': new_username,
                'user_id': user_id,
                'face_id': face_id,
                's3_key': filename,
                'created_at': datetime.now().isoformat(),
                'created_by': session['username'],
                'login_count': 0
            }
        )
        
        log_activity(session['user_id'], session['username'], 
                    f'created_user:{new_username}', 'success')
        
        print(f"[CREATE USER] User created successfully: {new_username}")
        return jsonify({
            'success': True,
            'message': 'User created successfully',
            'username': new_username
        }), 201
        
    except Exception as e:
        print(f"[CREATE USER] Error: {str(e)}")
        print(traceback.format_exc())
        return jsonify({'error': f'User creation failed: {str(e)}'}), 500

@app.route('/api/analytics')
@login_required
def api_analytics():
    """API: Get analytics data"""
    try:
        username = session['username']
        
        # Get user data
        response = users_table.get_item(Key={'username': username})
        user = response.get('Item', {})
        
        # Get recent logs
        logs_response = logs_table.scan(
            FilterExpression='username = :uname',
            ExpressionAttributeValues={':uname': username},
            Limit=10
        )
        
        # Get all users count
        all_users = users_table.scan(Select='COUNT')
        
        return jsonify({
            'username': username,
            'user_id': user.get('user_id'),
            'login_count': user.get('login_count', 0),
            'created_at': user.get('created_at'),
            'total_users': all_users['Count'],
            'recent_activity': logs_response.get('Items', [])[:5]
        }), 200
        
    except Exception as e:
        print(f"[ANALYTICS] Error: {str(e)}")
        return jsonify({'error': f'Failed to fetch analytics: {str(e)}'}), 500

@app.route('/api/logout', methods=['POST', 'GET'])
def api_logout():
    """API: Logout current user"""
    if 'username' in session:
        log_activity(session.get('user_id'), session['username'], 'logout', 'success')
        session.clear()
    
    if request.method == 'GET':
        flash('You have been logged out', 'success')
        return redirect(url_for('home'))
    
    return jsonify({'success': True, 'message': 'Logged out successfully'}), 200

# ==================== ERROR HANDLERS ====================

@app.errorhandler(404)
def not_found(e):
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Endpoint not found'}), 404
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_error(e):
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Internal server error'}), 500
    return render_template('500.html'), 500

if __name__ == '__main__':
    # Initialize AWS resources on startup
    init_aws_resources()
    
    print("\nStarting Flask application...")
    print(f"Server will be available at: http://0.0.0.0:5000")
    print("Press CTRL+C to quit\n")
    
    app.run(host='0.0.0.0', port=5000, debug=True)
