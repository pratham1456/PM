from flask import Flask, render_template, request, redirect, url_for, flash, session,jsonify
from flask_sqlalchemy import SQLAlchemy
from cryptography.fernet import Fernet
import os


# Initialize the Flask application
app = Flask(__name__)

# Set a strong secret key for session management (e.g., protecting cookies and user sessions)
app.secret_key = 'TrAcK@Jan2024'  # Replace with a strong secret key

# Configure the database connection (MSSQL with Windows Authentication) 
app.config['SQLALCHEMY_DATABASE_URI'] = ( 'mssql+pyodbc://HORIZON\\SQLEXPRESS/PM?driver=ODBC+Driver+17+for+SQL+Server&Trusted_Connection=yes&TrustServerCertificate=yes' ) 
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False # Disable modification tracking for performance


# Configure the database connection (PostgreSQL)
# app.config['SQLALCHEMY_DATABASE_URI'] = (
#     'postgresql+psycopg2://postgres:admin@localhost:5432/PM'
# )
# app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  

# Initialize the database instance
db = SQLAlchemy(app)

# Generate an encryption key for securing sensitive data (e.g., passwords)
# Ensure the key is stored securely (e.g., environment variables or secure vaults)
key = os.environ.get('ENCRYPTION_KEY').encode()  # Fetch the key from environment variables
cipher_suite = Fernet(key)  # Create a Fernet instance for encryption and decryption





# Define the User model representing a table in the database
class User(db.Model):
    # Define columns for the User table
    User_ID = db.Column(db.Integer, primary_key=True)         # Primary key (auto-incremented)
    FirstName = db.Column(db.String(200), nullable=False)     # User's first name
    LastName = db.Column(db.String(200), nullable=False)      # User's last name
    UserName = db.Column(db.String(200), nullable=False)      # Username for login
    Email = db.Column(db.String(200), nullable=False)         # User's email address
    Password = db.Column(db.String(200), nullable=False)      # Encrypted password
    UserRole = db.Column(db.String(200), nullable=False)      # User's role (e.g., Admin, HOD)
    Department = db.Column(db.String(200), nullable=False)    # User's department
    DisplayUser = db.Column(db.Boolean, default=True)         # Flag to indicate if user should be displayed

    def __repr__(self):
        # String representation of the User instance
        return f"<User {self.User_ID}>"


class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ipo_no = db.Column(db.String(100), nullable=False)
    name = db.Column(db.String(200), nullable=False)
    company_name = db.Column(db.String(200), nullable=False)
    departments = db.Column(db.String(500), nullable=False)
    start_date = db.Column(db.Date, nullable=False)
    target_date = db.Column(db.Date, nullable=False)
    total_estimation = db.Column(db.Float, nullable=False)
    actual_start_date = db.Column(db.Date, nullable=True)
    actual_target_date = db.Column(db.Date, nullable=True)
    actual_estimation = db.Column(db.Date, nullable=True)


    def __repr__(self):
        # String representation of the project instance
        return f"<User {self.id}>"



# Run database operations in the Flask app context
with app.app_context():
    db.create_all()  # Create database tables if they don't exist

    # Check if there are no users in the database
    if User.query.count() < 1:
        # Create a default admin user with encrypted password
        default_password = os.environ.get('Default password')  # Initial password
        encrypted_password = cipher_suite.encrypt(default_password.encode()).decode()  # Encrypt the password
        default_user = User(
            FirstName="Admin",
            LastName="User",
            UserName="admin",
            Email="admin@example.com",
            Password=encrypted_password,
            UserRole="Admin",
            Department='management',
            DisplayUser=False  # Set DisplayUser flag to False for default user
        )
        db.session.add(default_user)  # Add the user to the session
        db.session.commit()  # Save the user to the database
        print("Default admin user created. Username: admin, Password: 1234")


# Route for the home page (redirects to the Login page)
@app.route('/')
def home():
    return redirect(url_for('LoginPage'))


# Route for the login page
@app.route('/login', methods=['GET', 'POST'])
def LoginPage():
    if request.method == 'POST':  # Handle login form submission
        username = request.form['username']  # Entered username
        password = request.form['password']  # Entered password

        # Query the database for the user
        user = User.query.filter_by(UserName=username).first()
        if user:
            # Decrypt the stored password for validation
            decrypted_password = cipher_suite.decrypt(user.Password.encode()).decode()
            if password == decrypted_password:  # Validate the password
                session['user_id'] = user.User_ID  # Store user ID in session
                session['username'] = user.UserName  # Store username in session
                return redirect(url_for('ProjectPage'))  # Redirect to the Projects page
            else:
                flash('Invalid username or password', 'danger')  # Invalid password
        else:
            flash('Invalid username or password', 'danger')      # User not found
    return render_template('Login.html')


@app.route('/Projects', methods=['GET', 'POST'])
def ProjectPage():
    if 'user_id' not in session:
        return redirect(url_for('LoginPage'))
    
    # Retrieve the user_id from the session
    user_id = session.get('user_id')
    if user_id:
        user = User.query.get(user_id)
        user_role = user.UserRole
    else:
        user_role = None
    
    if request.method == 'POST':
        ipo_no = request.form['ipo_no']
        name = request.form['project_name']
        company_name = request.form['company_name']
        departments = ", ".join(request.form.getlist('departments'))
        start_date = request.form['start_date']
        target_date = request.form['target_date']
        total_estimation = float(request.form['total_estimation'])
        
        new_project = Project(
            ipo_no=ipo_no,
            name=name,
            company_name=company_name,
            departments=departments,
            start_date=start_date,
            target_date=target_date,
            total_estimation=total_estimation
        )
        db.session.add(new_project)
        db.session.commit()
        # flash('Project added successfully', 'success')
        return redirect(url_for('ProjectPage'))
    
    projects = Project.query.all()
    return render_template('project.html',user_role=user_role, projects=projects)

@app.route('/project/<int:project_id>')
def project_details(project_id):
    project = Project.query.get_or_404(project_id)
    user_id = session.get('user_id')
    if user_id:
        user = User.query.get(user_id)
        user_role = user.UserRole
    else:
        user_role = None
    return render_template('project_details.html', project=project,user_role=user_role)


@app.route('/edit_project/<int:project_id>', methods=['GET', 'POST'])
def edit_project(project_id):
    project = Project.query.get_or_404(project_id)
    
    if request.method == 'POST':
        project.ipo_no = request.form['ipo_no']
        project.name = request.form['name']
        project.company_name = request.form['company_name']
        project.departments = request.form['departments']
        project.start_date = request.form['start_date']
        project.target_date = request.form['target_date']
        project.total_estimation = float(request.form['total_estimation'])
        project.actual_start_date = request.form.get('actual_start_date') or None
        project.actual_target_date = request.form.get('actual_target_date') or None
        project.actual_estimation = request.form.get('actual_estimation') or None
        
        db.session.commit()
        # flash('Project updated successfully', 'success')
        return redirect(url_for('project_details', project_id=project.id))
    
    return render_template('edit_projects.html', project=project)



@app.route('/delete_project/<int:project_id>', methods=['POST'])
def delete_project(project_id):
    project = Project.query.get_or_404(project_id)  # Fetch project or return 404 if not found
    db.session.delete(project)  # Delete project from the database
    db.session.commit()  # Save changes
    
    # flash('Project deleted successfully', 'success')  # Flash success message
    return redirect(url_for('ProjectPage'))  # Redirect to projects list




# Route for the Users page (requires authentication)
@app.route('/Users', methods=['GET', 'POST'])
def UserPage():
    if 'user_id' not in session:
        return redirect(url_for('LoginPage'))  # Redirect to login if not authenticated

    user_id = session.get('user_id')
    if user_id:
        user = User.query.get(user_id)
        user_role = user.UserRole
        department_name = user.Department
    else:
        user_role = None
        department_name = None

    # Handle new user creation based on role
    if user_role == 'Admin':
        if request.method == 'POST':
            # Extract form data and create a new user
            first_name = request.form['first_name']
            last_name = request.form['last_name']
            username = request.form['username']
            email = request.form['email']
            password = request.form['password']
            userrole = request.form['user_role']
            department = request.form['department']

            encrypted_password = cipher_suite.encrypt(password.encode()).decode()
            new_user = User(
                FirstName=first_name,
                LastName=last_name,
                UserName=username,
                Email=email,
                Password=encrypted_password,
                UserRole=userrole,
                Department=department
            )
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('UserPage'))

    # Other roles (HOD and TL) can add users within their department
    elif user_role == 'HOD' or 'TL' and department_name == department_name:
        if request.method == 'POST':
            # HOD-specific logic for user creation
            first_name = request.form['first_name']
            last_name = request.form['last_name']
            username = request.form['username']
            email = request.form['email']
            password = request.form['password']
            userrole = request.form['user_role']

            encrypted_password = cipher_suite.encrypt(password.encode()).decode()
            new_user = User(
                FirstName=first_name,
                LastName=last_name,
                UserName=username,
                Email=email,
                Password=encrypted_password,
                UserRole=userrole,
                Department=department_name
            )
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('UserPage'))


    # Fetch all users to display
    users = User.query.filter_by(DisplayUser=True).all()
    return render_template('Users.html', users=users, user_role=user_role)


# Route for logging out the user
@app.route('/logout')
def logout():
    # Clear user session data
    session.pop('user_id', None)
    session.pop('username', None)
    flash('You have been logged out!', 'success')
    return redirect(url_for('LoginPage'))


# Entry point for running the Flask application
if __name__ == "__main__":
    # Run the Flask app on port 9000 in debug mode
    app.run(debug=True, port=9000)
