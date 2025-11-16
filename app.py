from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect, CSRFError
from wtforms import StringField, PasswordField, HiddenField, IntegerField, FloatField, SelectField, FileField
from wtforms.validators import DataRequired, Length, Email, NumberRange
import os
import base64
from io import BytesIO
from PIL import Image
import bcrypt
import secrets
import sqlite3
import uuid
import smtplib
from email.mime.text import MIMEText
from dotenv import load_dotenv
import PyPDF2
from docx import Document
import re
import json
from transformers import pipeline

# Load environment variables
load_dotenv()

# Initialize local T5 model
try:
    t5_pipeline = pipeline("text2text-generation", model="t5-small")
    print("Local T5 model initialized successfully")
except Exception as e:
    print(f"Failed to initialize local T5 model: {e}")
    t5_pipeline = None

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)
app.config['UPLOAD_FOLDER'] = 'Uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

csrf = CSRFProtect(app)

EMAIL_ADDRESS = os.getenv('EMAIL_ADDRESS')
EMAIL_PASSWORD = os.getenv('EMAIL_PASSWORD')

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

def init_db():
    with sqlite3.connect('shopkeepers.db') as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS shopkeepers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            mobile TEXT,
            password TEXT NOT NULL,
            photo_path TEXT,
            verified BOOLEAN NOT NULL DEFAULT 0,
            verification_token TEXT
        )''')
        conn.execute('''CREATE TABLE IF NOT EXISTS inventory (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            shopkeeper_id INTEGER NOT NULL,
            item_name TEXT NOT NULL,
            quantity INTEGER NOT NULL,
            price REAL NOT NULL,
            FOREIGN KEY (shopkeeper_id) REFERENCES shopkeepers(id)
        )''')
        conn.execute('''CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            shopkeeper_id INTEGER NOT NULL,
            item_id INTEGER NOT NULL,
            quantity INTEGER NOT NULL,
            order_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (shopkeeper_id) REFERENCES shopkeepers(id),
            FOREIGN KEY (item_id) REFERENCES inventory(id)
        )''')
        conn.commit()

init_db()

class RegisterForm(FlaskForm):
    first_name = StringField('First Name', validators=[DataRequired()])
    last_name = StringField('Last Name', validators=[DataRequired()])
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    mobile = StringField('Mobile Number', validators=[Length(min=0, max=15)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    photo = HiddenField('Photo', validators=[DataRequired()])

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])

class InventoryForm(FlaskForm):
    item_name = StringField('Item Name', validators=[DataRequired(), Length(min=1, max=50)])
    quantity = IntegerField('Quantity', validators=[DataRequired(), NumberRange(min=0)])
    price = FloatField('Price ($)', validators=[DataRequired(), NumberRange(min=0.01)])

class FileUploadForm(FlaskForm):
    file = FileField('Upload PDF/Word File', validators=[DataRequired()])

class VoiceInventoryForm(FlaskForm):
    transcript = StringField('Transcript', validators=[DataRequired()])

class ConfirmVoiceInventoryForm(FlaskForm):
    items = HiddenField('Items', validators=[DataRequired()])

class EditInventoryItemForm(FlaskForm):
    item_name = StringField('Item Name', validators=[DataRequired(), Length(min=1, max=50)])
    quantity = IntegerField('Quantity', validators=[DataRequired(), NumberRange(min=0)])
    price = FloatField('Price ($)', validators=[DataRequired(), NumberRange(min=0.01)])

class OrderForm(FlaskForm):
    item_id = SelectField('Item', coerce=int, validators=[DataRequired()])
    quantity = IntegerField('Quantity', validators=[DataRequired(), NumberRange(min=1)])

def send_verification_email(email, token):
    try:
        if not EMAIL_ADDRESS or not EMAIL_PASSWORD:
            print("Error: EMAIL_ADDRESS or EMAIL_PASSWORD not set in .env")
            return False
        verify_url = f"http://localhost:5000/verify/{token}"
        msg = MIMEText(f'Click the link to verify your email: <a href="{verify_url}">Verify Email</a>', 'html')
        msg['Subject'] = 'Verify Your Email - Shopkeeper Assistant'
        msg['From'] = f"Shopkeeper Assistant <{EMAIL_ADDRESS}>"
        msg['To'] = email

        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            server.sendmail(EMAIL_ADDRESS, email, msg.as_string())
        print(f"Verification email sent to {email}")
        return True
    except smtplib.SMTPAuthenticationError:
        print("SMTP Authentication Error: Check EMAIL_ADDRESS and EMAIL_PASSWORD")
        return False
    except smtplib.SMTPException as e:
        print(f"SMTP Error: {e}")
        return False
    except Exception as e:
        print(f"Unexpected error sending email: {e}")
        return False

def parse_inventory_file(file):
    items = []
    try:
        if file.filename.endswith('.pdf'):
            pdf_reader = PyPDF2.PdfReader(file)
            text = ''
            for page in pdf_reader.pages:
                text += page.extract_text() or ''
        elif file.filename.endswith('.docx'):
            doc = Document(file)
            text = '\n'.join([para.text for para in doc.paragraphs])
        else:
            return None, 'Unsupported file format. Use PDF or Word (.docx).'

        pattern = r'Item:\s*([^\,]+),\s*Quantity:\s*(\d+),\s*Price:\s*(\d+\.?\d*)'
        matches = re.findall(pattern, text, re.IGNORECASE)
        for match in matches:
            item_name, quantity, price = match
            items.append({
                'item_name': item_name.strip(),
                'quantity': int(quantity),
                'price': float(price)
            })
        if not items:
            return None, 'No valid inventory data found in the file.'
        return items, None
    except Exception as e:
        return None, f'Error parsing file: {str(e)}'

def parse_voice_transcript(transcript):
    items = []
    try:
        # Normalize transcript
        transcript = transcript.lower().strip().replace(' dollars', '').replace(' each', '')
        # Remove commas in numbers
        transcript = re.sub(r'(\d+),(\d+)', r'\1\2', transcript)
        print("Normalized transcript:", transcript)

        # Local T5 parsing
        if t5_pipeline:
            prompt = (
                "Parse the following transcript into a JSON list of items, where each item has 'item_name' (string), "
                "'quantity' (integer), and 'price' (float, two decimal places). Remove filler words like 'I want', 'please', "
                "'at', 'for', 'dollars'. Example transcript: 'I want 10 laptops for 500, 20 phones at 600'. "
                "Example output: [{\"item_name\": \"laptops\", \"quantity\": 10, \"price\": 500.00}, "
                "{\"item_name\": \"phones\", \"quantity\": 20, \"price\": 600.00}]. Transcript: {transcript}"
            ).format(transcript=transcript)
            t5_output = t5_pipeline(prompt, max_length=200, num_beams=4, early_stopping=True)[0]['generated_text']
            print("Local T5 output:", t5_output)
            try:
                items = json.loads(t5_output)
                # Validate and normalize items
                validated_items = []
                for item in items:
                    if isinstance(item, dict) and 'item_name' in item and 'quantity' in item and 'price' in item:
                        try:
                            quantity = int(item['quantity'])
                            price = round(float(str(item['price']).replace('$', '')), 2)
                            item_name = item['item_name'].strip()
                            if quantity > 0 and price > 0 and item_name:
                                validated_items.append({
                                    'item_name': item_name,
                                    'quantity': quantity,
                                    'price': price
                                })
                        except (ValueError, TypeError):
                            continue
                items = validated_items
            except json.JSONDecodeError:
                print("Local T5 output not valid JSON, falling back to regex")

        # Regex fallback
        if not items:
            # Split on 'and', 'then', or periods, preserving numbers
            sentences = [s.strip() for s in re.split(r'\s+and\s+|\s+then\s+|[.]', transcript) if s.strip()]
            print("Sentences:", sentences)
            pattern = r'(\d+|ten|twenty)\s+([^\s].*?)\s+(?:at|for)?\s*(\d+\.?\d*)'
            for sentence in sentences:
                if len(sentence.split()) < 3:
                    continue
                match = re.match(pattern, sentence, re.IGNORECASE)
                if match:
                    qty_str = match.group(1).lower()
                    qty_map = {'ten': 10, 'twenty': 20}
                    quantity = qty_map.get(qty_str, int(qty_str))
                    item_name = match.group(2).strip()
                    price_str = match.group(3)
                    price = round(float(price_str) if '.' in price_str else float(f"{price_str}.00"), 2)
                    item_name = re.sub(r'\b(add|at|for|please|want|i|then)\b', '', item_name, flags=re.IGNORECASE).strip()
                    if quantity and item_name and price:
                        items.append({
                            'item_name': item_name,
                            'quantity': quantity,
                            'price': price
                        })

        # Remove duplicates
        unique_items = []
        seen = set()
        for item in items:
            key = (item['item_name'].lower(), item['quantity'], item['price'])
            if key not in seen:
                seen.add(key)
                unique_items.append(item)
        items = unique_items

        print("Parsed items:", items)
        return items if items else None
    except Exception as e:
        print(f"Error parsing transcript: {e}")
        return None

@app.route('/')
def index():
    return redirect(url_for('register'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    login_form = LoginForm()
    if request.method == 'POST':
        print("Form submitted with data:", dict(request.form))
        try:
            if form.validate_on_submit():
                print("Form validation passed")
                first_name = form.first_name.data
                last_name = form.last_name.data
                username = form.username.data
                email = form.email.data
                mobile = form.mobile.data or None
                password = bcrypt.hashpw(form.password.data.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
                photo_base64 = form.photo.data
                verification_token = secrets.token_urlsafe(32)

                photo_path = None
                if photo_base64:
                    try:
                        if ',' in photo_base64:
                            photo_base64 = photo_base64.split(',')[1]
                        photo_data = base64.b64decode(photo_base64)
                        image = Image.open(BytesIO(photo_data))
                        if image.format not in ['PNG', 'JPEG']:
                            flash('Only PNG or JPEG images are allowed.', 'error')
                            print("Photo format error: Not PNG or JPEG")
                            return render_template('index.html', form=form, login_form=login_form, show_register=True)
                        filename = f"{uuid.uuid4()}.{image.format.lower()}"
                        photo_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                        image.save(photo_path)
                        print(f"Photo saved to {photo_path}")
                    except Exception as e:
                        flash('Invalid photo data.', 'error')
                        print(f"Photo processing error: {e}")
                        return render_template('index.html', form=form, login_form=login_form, show_register=True)

                try:
                    with sqlite3.connect('shopkeepers.db') as conn:
                        cursor = conn.execute('INSERT INTO shopkeepers (first_name, last_name, username, email, mobile, password, photo_path, verified, verification_token) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
                                            (first_name, last_name, username, email, mobile, password, photo_path, 0, verification_token))
                        conn.commit()
                        shopkeeper_id = cursor.lastrowid
                    print("User data inserted into database")
                    session['shopkeeper_id'] = shopkeeper_id
                except sqlite3.IntegrityError as e:
                    if 'username' in str(e).lower():
                        flash('Username already exists.', 'error')
                        print("Database error: Username already exists")
                    elif 'email' in str(e).lower():
                        flash('Email already exists.', 'error')
                        print("Database error: Email already exists")
                    else:
                        flash('Registration failed. Please try again.', 'error')
                        print(f"Database error: {e}")
                    return render_template('index.html', form=form, login_form=login_form, show_register=True)
                except Exception as e:
                    flash('Registration failed. Please try again.', 'error')
                    print(f"Unexpected database error: {e}")
                    return render_template('index.html', form=form, login_form=login_form, show_register=True)

                if send_verification_email(email, verification_token):
                    flash('Registration successful! Please check your email to verify your account.', 'success')
                    print("Redirecting to login after successful registration")
                    return redirect(url_for('login'))
                else:
                    flash('Registration successful, but email sending failed. Contact support.', 'error')
                    print("Redirecting to login after email sending failure")
                    return redirect(url_for('login'))
            else:
                print("Form validation failed. Errors:", form.errors)
                flash(f'Form validation failed: {form.errors}', 'error')
        except CSRFError as e:
            print(f"CSRF validation failed: {e}")
            flash('CSRF token invalid or missing. Please refresh and try again.', 'error')
        except Exception as e:
            print(f"Unexpected error in register route: {e}")
            flash('An unexpected error occurred. Please try again.', 'error')
    return render_template('index.html', form=form, login_form=login_form, show_register=True)

@app.route('/verify/<token>')
def verify_email(token):
    try:
        with sqlite3.connect('shopkeepers.db') as conn:
            cursor = conn.execute('SELECT id FROM shopkeepers WHERE verification_token = ? AND verified = 0', (token,))
            result = cursor.fetchone()
            if result:
                conn.execute('UPDATE shopkeepers SET verified = 1, verification_token = NULL WHERE id = ?', (result[0],))
                conn.commit()
                flash('Email verified successfully! You can now log in.', 'success')
                print(f"Email verified for token {token}")
            else:
                flash('Invalid or expired verification link.', 'error')
                print(f"Invalid verification token: {token}")
    except Exception as e:
        flash('Verification failed. Please try again.', 'error')
        print(f"Verification error: {e}")
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = RegisterForm()
    login_form = LoginForm()
    if request.method == 'POST':
        print("Login form submitted with data:", dict(request.form))
        try:
            if login_form.validate_on_submit():
                print("Login form validation passed")
                username = login_form.username.data
                password = login_form.password.data.encode('utf-8')
                with sqlite3.connect('shopkeepers.db') as conn:
                    cursor = conn.execute('SELECT id, password, verified FROM shopkeepers WHERE username = ?', (username,))
                    result = cursor.fetchone()
                    if result and bcrypt.checkpw(password, result[1].encode('utf-8')):
                        if result[2]:
                            session['shopkeeper_id'] = result[0]
                            flash('Login successful!', 'success')
                            print("Login successful")
                            return redirect(url_for('dashboard'))
                        else:
                            flash('Please verify your email before logging in.', 'error')
                            print("Login failed: Email not verified")
                    else:
                        flash('Invalid username or password.', 'error')
                        print("Login failed: Invalid credentials")
            else:
                print("Login form validation failed. Errors:", login_form.errors)
                flash(f'Login form validation failed: {login_form.errors}', 'error')
        except CSRFError as e:
            print(f"CSRF validation failed in login: {e}")
            flash('CSRF token invalid or missing. Please refresh and try again.', 'error')
        except Exception as e:
            print(f"Unexpected error in login route: {e}")
            flash('An unexpected error occurred. Please try again.', 'error')
    return render_template('index.html', form=form, login_form=login_form, show_register=False)

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'shopkeeper_id' not in session:
        flash('Please log in to access the dashboard.', 'error')
        print("Unauthorized access to dashboard: Not logged in")
        return redirect(url_for('login'))

    shopkeeper_id = session['shopkeeper_id']
    order_form = OrderForm()

    with sqlite3.connect('shopkeepers.db') as conn:
        cursor = conn.execute('SELECT id, item_name FROM inventory WHERE shopkeeper_id = ?', (shopkeeper_id,))
        items = cursor.fetchall()
        order_form.item_id.choices = [(item[0], item[1]) for item in items]

    if request.method == 'POST' and 'order_form' in request.form:
        print("Order form submitted with data:", dict(request.form))
        try:
            if order_form.validate_on_submit():
                print("Order form validation passed")
                item_id = order_form.item_id.data
                order_quantity = order_form.quantity.data

                with sqlite3.connect('shopkeepers.db') as conn:
                    cursor = conn.execute('SELECT item_name, quantity FROM inventory WHERE id = ? AND shopkeeper_id = ?', (item_id, shopkeeper_id))
                    result = cursor.fetchone()
                    if result and result[1] >= order_quantity:
                        item_name = result[0]
                        new_quantity = result[1] - order_quantity
                        conn.execute('UPDATE inventory SET quantity = ? WHERE id = ?', (new_quantity, item_id))
                        conn.execute('INSERT INTO orders (shopkeeper_id, item_id, quantity) VALUES (?, ?, ?)', (shopkeeper_id, item_id, order_quantity))
                        conn.commit()
                        flash(f'Order for {order_quantity} {item_name} placed successfully.', 'success')
                        print(f"Order placed: {item_name}, quantity: {order_quantity}")
                    else:
                        flash('Insufficient stock or invalid item.', 'error')
                        print(f"Order failed: Insufficient stock for item_id {item_id}")
            else:
                print("Order form validation failed. Errors:", order_form.errors)
                flash(f'Order form validation failed: {order_form.errors}', 'error')
        except CSRFError as e:
            print(f"CSRF validation failed in order: {e}")
            flash('CSRF token invalid or missing. Please refresh and try again.', 'error')
        except Exception as e:
            print(f"Unexpected error in order: {e}")
            flash('An unexpected error occurred. Please try again.', 'error')

    with sqlite3.connect('shopkeepers.db') as conn:
        cursor = conn.execute('SELECT item_name, quantity, price FROM inventory WHERE shopkeeper_id = ?', (shopkeeper_id,))
        inventory = cursor.fetchall()

    return render_template('dashboard.html', order_form=order_form, inventory=inventory, shopkeeper_id=shopkeeper_id)

@app.route('/update_inventory', methods=['GET', 'POST'])
def update_inventory():
    if 'shopkeeper_id' not in session:
        flash('Please log in to access this page.', 'error')
        print("Unauthorized access to update_inventory: Not logged in")
        return redirect(url_for('login'))

    shopkeeper_id = session['shopkeeper_id']
    manual_form = InventoryForm()
    file_form = FileUploadForm()
    voice_form = VoiceInventoryForm()

    with sqlite3.connect('shopkeepers.db') as conn:
        cursor = conn.execute('SELECT id, item_name, quantity, price FROM inventory WHERE shopkeeper_id = ?', (shopkeeper_id,))
        inventory_items = cursor.fetchall()

    if request.method == 'POST' and 'manual_form' in request.form:
        print("Manual inventory form submitted with data:", dict(request.form))
        try:
            if manual_form.validate_on_submit():
                print("Manual inventory form validation passed")
                item_name = manual_form.item_name.data
                quantity = manual_form.quantity.data
                price = manual_form.price.data

                with sqlite3.connect('shopkeepers.db') as conn:
                    cursor = conn.execute('SELECT id, quantity FROM inventory WHERE shopkeeper_id = ? AND item_name = ?', (shopkeeper_id, item_name))
                    result = cursor.fetchone()
                    if result:
                        new_quantity = result[1] + quantity
                        conn.execute('UPDATE inventory SET quantity = ?, price = ? WHERE id = ?', (new_quantity, price, result[0]))
                        flash(f'Updated {item_name} in inventory.', 'success')
                        print(f"Updated inventory: {item_name}, new quantity: {new_quantity}")
                    else:
                        conn.execute('INSERT INTO inventory (shopkeeper_id, item_name, quantity, price) VALUES (?, ?, ?, ?)', (shopkeeper_id, item_name, quantity, price))
                        flash(f'Added {item_name} to inventory.', 'success')
                        print(f"Added to inventory: {item_name}, quantity: {quantity}")
                    conn.commit()
            else:
                print("Manual inventory form validation failed. Errors:", manual_form.errors)
                flash(f'Manual inventory form validation failed: {manual_form.errors}', 'error')
        except CSRFError as e:
            print(f"CSRF validation failed in manual inventory: {e}")
            flash('CSRF token invalid or missing. Please refresh and try again.', 'error')
        except Exception as e:
            print(f"Unexpected error in manual inventory update: {e}")
            flash('An unexpected error occurred. Please try again.', 'error')

    if request.method == 'POST' and 'file_form' in request.form:
        print("File upload form submitted")
        try:
            if file_form.validate_on_submit():
                print("File upload form validation passed")
                file = file_form.file.data
                items, error = parse_inventory_file(file)
                if error:
                    flash(error, 'error')
                    print(f"File parsing error: {error}")
                else:
                    with sqlite3.connect('shopkeepers.db') as conn:
                        for item in items:
                            cursor = conn.execute('SELECT id, quantity FROM inventory WHERE shopkeeper_id = ? AND item_name = ?', (shopkeeper_id, item['item_name']))
                            result = cursor.fetchone()
                            if result:
                                new_quantity = result[1] + item['quantity']
                                conn.execute('UPDATE inventory SET quantity = ?, price = ? WHERE id = ?', (new_quantity, item['price'], result[0]))
                                flash(f'Updated {item["item_name"]} in inventory.', 'success')
                                print(f"Updated inventory from file: {item['item_name']}, new quantity: {new_quantity}")
                            else:
                                conn.execute('INSERT INTO inventory (shopkeeper_id, item_name, quantity, price) VALUES (?, ?, ?, ?)', 
                                            (shopkeeper_id, item['item_name'], item['quantity'], item['price']))
                                flash(f'Added {item["item_name"]} to inventory.', 'success')
                                print(f"Added to inventory from file: {item['item_name']}, quantity: {item['quantity']}")
                        conn.commit()
            else:
                print("File upload form validation failed. Errors:", file_form.errors)
                flash(f'File upload form validation failed: {file_form.errors}', 'error')
        except CSRFError as e:
            print(f"CSRF validation failed in file upload: {e}")
            flash('CSRF token invalid or missing. Please refresh and try again.', 'error')
        except Exception as e:
            print(f"Unexpected error in file upload: {e}")
            flash('An unexpected error occurred. Please try again.', 'error')

    if request.method == 'POST' and 'voice_form' in request.form:
        print("Voice inventory form submitted with data:", dict(request.form))
        try:
            if voice_form.validate_on_submit():
                print("Voice inventory form validation passed")
                transcript = voice_form.transcript.data
                items = parse_voice_transcript(transcript)
                if not items:
                    flash('Could not parse any items. Try speaking clearly, e.g., "I want 10 laptops for 999.99, 20 phones at 499.99."', 'error')
                    print(f"Voice parsing failed: {transcript}")
                else:
                    session['voice_items'] = items
                    print(f"Parsed voice items: {items}")
                    return redirect(url_for('confirm_voice_inventory'))
            else:
                print("Voice inventory form validation failed. Errors:", voice_form.errors)
                flash(f'Voice inventory form validation failed: {voice_form.errors}', 'error')
        except CSRFError as e:
            print(f"CSRF validation failed in voice inventory: {e}")
            flash('CSRF token invalid or missing. Please refresh and try again.', 'error')
        except Exception as e:
            print(f"Unexpected error in voice inventory update: {e}")
            flash('An unexpected error occurred. Please try again.', 'error')

    return render_template('update_inventory.html', manual_form=manual_form, file_form=file_form, voice_form=voice_form, inventory_items=inventory_items)

@app.route('/confirm_voice_inventory', methods=['GET', 'POST'])
def confirm_voice_inventory():
    if 'shopkeeper_id' not in session:
        flash('Please log in to access this page.', 'error')
        print("Unauthorized access to confirm_voice_inventory: Not logged in")
        return redirect(url_for('login'))

    shopkeeper_id = session['shopkeeper_id']
    confirm_form = ConfirmVoiceInventoryForm()

    # Load items from session
    items = session.get('voice_items', [])
    if not items:
        flash('No items to confirm. Please use voice input again.', 'error')
        print("No voice items in session")
        return redirect(url_for('update_inventory'))

    # Populate form items field
    confirm_form.items.data = json.dumps(items)

    if request.method == 'POST':
        print("Confirm voice inventory form submitted with data:", dict(request.form))
        try:
            if confirm_form.validate_on_submit():
                print("Confirm voice inventory form validation passed")
                items = json.loads(confirm_form.items.data)
                with sqlite3.connect('shopkeepers.db') as conn:
                    for item in items:
                        cursor = conn.execute('SELECT id, quantity FROM inventory WHERE shopkeeper_id = ? AND item_name = ?', 
                                            (shopkeeper_id, item['item_name']))
                        result = cursor.fetchone()
                        if result:
                            new_quantity = result[1] + item['quantity']
                            conn.execute('UPDATE inventory SET quantity = ?, price = ? WHERE id = ?', 
                                        (new_quantity, item['price'], result[0]))
                            flash(f'Updated {item["item_name"]} in inventory.', 'success')
                            print(f"Updated inventory from voice: {item['item_name']}, new quantity: {new_quantity}")
                        else:
                            conn.execute('INSERT INTO inventory (shopkeeper_id, item_name, quantity, price) VALUES (?, ?, ?, ?)', 
                                        (shopkeeper_id, item['item_name'], item['quantity'], item['price']))
                            flash(f'Added {item["item_name"]} to inventory.', 'success')
                            print(f"Added to inventory from voice: {item['item_name']}, quantity: {item['quantity']}")
                    conn.commit()
                session.pop('voice_items', None)
                return redirect(url_for('update_inventory'))
            else:
                print("Confirm voice inventory form validation failed. Errors:", confirm_form.errors)
                flash(f'Confirm form validation failed: {confirm_form.errors}', 'error')
        except CSRFError as e:
            print(f"CSRF validation failed in confirm voice inventory: {e}")
            flash('CSRF token invalid or missing. Please refresh and try again.', 'error')
        except Exception as e:
            print(f"Unexpected error in confirm voice inventory: {e}")
            flash('An unexpected error occurred. Please try again.', 'error')

    return render_template('confirm_voice_inventory.html', confirm_form=confirm_form, items=items)

@app.route('/edit_inventory_item/<int:item_id>', methods=['GET', 'POST'])
def edit_inventory_item(item_id):
    if 'shopkeeper_id' not in session:
        flash('Please log in to access this page.', 'error')
        print("Unauthorized access to edit_inventory_item: Not logged in")
        return redirect(url_for('login'))

    shopkeeper_id = session['shopkeeper_id']
    edit_form = EditInventoryItemForm()

    with sqlite3.connect('shopkeepers.db') as conn:
        cursor = conn.execute('SELECT id, item_name, quantity, price FROM inventory WHERE id = ? AND shopkeeper_id = ?', (item_id, shopkeeper_id))
        item = cursor.fetchone()
        if not item:
            flash('Item not found or you do not have permission to edit it.', 'error')
            print(f"Item not found: id={item_id}, shopkeeper_id={shopkeeper_id}")
            return redirect(url_for('update_inventory'))

    if request.method == 'POST':
        print("Edit inventory item form submitted with data:", dict(request.form))
        try:
            if edit_form.validate_on_submit():
                print("Edit inventory item form validation passed")
                item_name = edit_form.item_name.data
                quantity = edit_form.quantity.data
                price = edit_form.price.data

                with sqlite3.connect('shopkeepers.db') as conn:
                    conn.execute('UPDATE inventory SET item_name = ?, quantity = ?, price = ? WHERE id = ? AND shopkeeper_id = ?',
                                (item_name, quantity, price, item_id, shopkeeper_id))
                    conn.commit()
                flash(f'Updated {item_name} in inventory.', 'success')
                print(f"Updated inventory item: id={item_id}, name={item_name}, quantity={quantity}, price={price}")
                return redirect(url_for('update_inventory'))
            else:
                print("Edit inventory item form validation failed. Errors:", edit_form.errors)
                flash(f'Edit form validation failed: {edit_form.errors}', 'error')
        except CSRFError as e:
            print(f"CSRF validation failed in edit inventory item: {e}")
            flash('CSRF token invalid or missing. Please refresh and try again.', 'error')
        except Exception as e:
            print(f"Unexpected error in edit inventory item: {e}")
            flash('An unexpected error occurred. Please try again.', 'error')

    edit_form.item_name.data = item[1]
    edit_form.quantity.data = item[2]
    edit_form.price.data = item[3]

    return render_template('edit_inventory_item.html', edit_form=edit_form, item_id=item_id, item_name=item[1])

@app.route('/logout')
def logout():
    session.pop('shopkeeper_id', None)
    flash('Logged out successfully.', 'success')
    print("User logged out")
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)