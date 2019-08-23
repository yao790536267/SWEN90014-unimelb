from flask import Flask, render_template, flash, session, redirect, url_for, logging, request, jsonify 
from flask_mysqldb import MySQL
from functools import wraps
from wtforms import Form, DateField, StringField, TextAreaField, PasswordField, validators, StringField, SubmitField, DateTimeField, SelectField
from passlib.hash import sha256_crypt
import datetime

app = Flask(__name__)

# init database connection settings
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'swen90014'
app.config['MYSQL_PASSWORD'] = 'swen90014'
app.config['MYSQL_DB'] = 'rmh'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

# init MYSQL
mysql = MySQL(app)

# check if user has logged in
def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Unauthorized, Please login', 'danger')
            return redirect(url_for('login'))
    return wrap

# check if user is an administrator or super administrator
def is_administrator(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if  session.get('staffType') == 'admin' or session.get('staffType') == 'super':
            return f(*args, **kwargs)
        else:
            flash('Unauthorized Access', 'danger')
            return redirect(url_for('index'))
    return wrap

#======================================================================Login & Logout=================================================================#
@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods = ['GET','POST'])
def login():   
    # check if logged_in
    if session.get('logged_in') and session.get('staffType'):
        if session['staffType'] == 'admin' or session['staffType'] == 'super':
            return redirect(url_for('accountManagement')) 
        else:
            return redirect(url_for('patientProfile')) 
    else:
        # get form data
        loginForm = LoginForm(request.form)
        if request.method == 'POST' and loginForm.validate(): 
            # validate with database
            email = loginForm.email.data
            password_candidate = loginForm.password.data
            cur = mysql.connection.cursor()
            result = cur.execute("SELECT * FROM staffs where email = %s", [email])
            # email correct
            if result > 0:
                data = cur.fetchone()
                password = data['password']
                # password correct
                if sha256_crypt.verify(password_candidate, password):
                    # app.logger.error('PASSWORD MATCHED')
                    # add to session
                    session['logged_in'] = True
                    session['email'] = data['email']
                    session['staffName'] = data['firstname'] +' '+ data['lastname']
                    session['staffType'] = data['staffType']
                    # for auto-complete
                    result = cur.execute("SELECT * FROM medicines")
                    session['medicines'] = cur.fetchall()
                    cur.close()
                    if session['staffType'] == 'admin' or session['staffType'] == 'super':
                        # jump to management page
                        return redirect(url_for('accountManagement'))
                    else:
                        return redirect(url_for('patientProfile'))
                # wrong password
                else:
                    cur.close()
                    flash('WRONG PASSWORD','danger')
            # no email matched in database  
            else:
                cur.close()
                flash('NO USER MATCHED','danger')
    # render login page with parameter
    return render_template('login.html', form=loginForm)

@app.route('/about')
def about():
    # render about page
    return render_template('about.html')

@app.route('/documents')
def documents():
    # render documents page
    return render_template('documents.html')

# API for user logout
@app.route('/logout')
@is_logged_in
def logout():   
    # clear the session and return to login page
    session.clear()
    # return to login page
    return redirect(url_for('index'))

#======================================================================Account Management=================================================================#
# API for account management page
@app.route('/accountManagement', methods = ['GET','POST'])
@is_logged_in
@is_administrator
def accountManagement():
    # init forms
    addAccountForm = AddAccountForm()
    editAccountForm = EditAccountForm()
    # Jinja flag
    staffs = 'empty'
    # get accounts from database
    cur = mysql.connection.cursor()
    result = cur.execute("SELECT * FROM staffs")
    # if staff exist
    if result > 0:
        staffs = cur.fetchall()
        cur.close()
    # if staff not exist
    else:
        cur.close()
        flash('No Record','danger')
    # render manage account with parameters
    return render_template('manageAccount.html', staffs = staffs, addAccountForm = addAccountForm, editAccountForm = editAccountForm)

# API for adding new account
@app.route('/accountManagement/addAccount', methods = ['GET','POST'])
@is_logged_in
@is_administrator
def addAccount():
    # get form data
    addAccountForm = AddAccountForm(request.form)
    # check if request and form are valid
    if request.method == 'POST' and addAccountForm.validate():
        # store data from form
        email = addAccountForm.email.data
        firstname = addAccountForm.firstname.data
        lastname = addAccountForm.lastname.data
        staffType = addAccountForm.staffType.data
        password = sha256_crypt.hash(addAccountForm.password.data)
        # database connection
        cur = mysql.connection.cursor()
        result = cur.execute("SELECT * FROM staffs where email = %s", [email])
        # if staff exist
        if result > 0:
            flash('Staff Already Exist','danger')
        # if staff not exist
        else:
            cur.execute("INSERT INTO staffs (email, firstname, lastname, staffType, password) values (%s,%s,%s,%s,%s)", [email,firstname,lastname,staffType,password] )
            # commit to database
            mysql.connection.commit()
            flash('Success','success')
        cur.close()
    else:
        flash('Invalid Form','danger')
    # return to account management page
    return redirect(url_for('accountManagement'))

# API for editing account 
@app.route('/accountManagement/editAccount', methods = ['GET','POST'])
@is_logged_in
@is_administrator
def editAccount():
    # get form data
    editAccountForm = EditAccountForm(request.form)
    # check if request and form are valid
    if request.method == 'POST' and editAccountForm.validate():
        # store data from form
        email = editAccountForm.email.data
        firstname = editAccountForm.firstname.data
        lastname = editAccountForm.lastname.data
        staffType = editAccountForm.staffType.data
        password = sha256_crypt.hash(editAccountForm.password.data)
        # database connection
        cur = mysql.connection.cursor()
        result = cur.execute("SELECT * FROM staffs where email = %s", [email])
        # if staff exist
        if result > 0:
            statement = "UPDATE staffs SET firstname=%s, lastname=%s, staffType=%s, password=%s where email=%s"
            cur.execute(statement, [firstname,lastname,staffType,password,email])
            # commit to database
            mysql.connection.commit()
            flash('Success','success')
        # if staff not exist
        else:
            flash('Staff Not Exist','danger')
        cur.close()
    else:
        flash('Invalid Form','danger')
    # return to account management page
    return redirect(url_for('accountManagement'))

# API for deleting account 
@app.route('/accountManagement/deleteAccount/<string:email>', methods = ['GET','POST'])
@is_logged_in
@is_administrator
def deleteAccount(email):
    # database connection
    cur = mysql.connection.cursor()
    result = cur.execute("SELECT * FROM staffs WHERE email = %s", [email])
    # if staff exist
    if result > 0:
        cur.execute("DELETE FROM staffs WHERE email = %s", [email])
        #commit
        mysql.connection.commit()
        cur.close()
        flash('Success','success')
    # if staff not exist
    else:
        cur.close()
        flash('Staff Not Exist','danger')
    # return to account management page
    return redirect(url_for('accountManagement'))

# API for resetting password (reset to 123456) 
@app.route('/accountManagement/resetPassAccount/<string:email>', methods = ['GET','POST'])
@is_logged_in
@is_administrator
def resetPassAccount(email):
    # set default password here
    password = sha256_crypt.hash('123456')
    # database connection
    cur = mysql.connection.cursor()
    result = cur.execute("SELECT * FROM staffs WHERE email = %s", [email])
    # if staff exist
    if result > 0:
        cur.execute("UPDATE staffs SET password = %s WHERE email = %s", [password,email])
        # commit
        mysql.connection.commit()
        cur.close()
        flash('Success','success')
    # if staff not exist
    else:
        cur.close()
        flash('Staff Not Exist','danger')
    # return to account management page
    return redirect(url_for('accountManagement'))

#======================================================================Medicine Management=================================================================#
# API for medicine management page
@app.route('/medicineManagement', methods = ['GET','POST'])
@is_logged_in
def medicineManagement():
    # init forms
    medicineForm = MedicineForm()
    # Jinja flag
    medicines = None
    # database connection
    cur = mysql.connection.cursor()
    result = cur.execute("SELECT * FROM medicines")
    # if medicine exist
    if result > 0:
        medicines = cur.fetchall()
    # if medicine not exist
    else:
        flash('No Medicine Record','success')
    cur.close()
    # render manage medicine page
    return render_template('manageMedicine.html',medicines=medicines, medicineForm=medicineForm)

# API for medicine search bar
@app.route('/medicineManagement/search', methods = ['GET','POST'])
@is_logged_in
def searchMedicine():
    # get form data
    medicineForm = MedicineForm(request.form)
    # Jinja flag
    medicines = None
    # check if request exist and form valid
    if request.method == 'POST' and medicineForm.validate():
        medicineName = medicineForm.medicineName.data
        # database connection
        cur = mysql.connection.cursor()
        result = cur.execute("SELECT * FROM medicines where medicineName = %s",[medicineName])
        # if medicine exist
        if result > 0:
            medicines = cur.fetchall()
        # if medicine not exist
        else:
            flash('No Such Medicine','danger')
        cur.close()
    else:
        flash('Invalid Form','danger')
        # jump to manage medicine page
        return redirect(url_for('medicineManagement'))
    # render manage medicine page
    return render_template('manageMedicine.html',medicines=medicines, medicineForm=medicineForm)

# API for adding medicine
@app.route('/medicineManagement/addMedicine', methods = ['GET','POST'])
@is_logged_in
def addMedicine():
    # get form data
    medicineForm = MedicineForm(request.form)
    # check if request exist and form valid
    if request.method == 'POST' and medicineForm.validate():
        medicineName = medicineForm.medicineName.data
        # database connection
        cur = mysql.connection.cursor()
        result = cur.execute("SELECT * FROM medicines where medicineName = %s", [medicineName])
        # if medicine exist
        if result > 0:
            flash('Medicine Already Exist','danger')
        # if medicine not exist
        else:
            cur.execute("INSERT INTO medicines (medicineName) values (%s)", [medicineName] )
            # commit
            mysql.connection.commit()
            # for auto-complete
            result = cur.execute("SELECT * FROM medicines")
            session['medicines'] = cur.fetchall()
            flash('Success','success')
        cur.close()
    else:
        flash('Invalid Form','danger')
    # jump tp manage medicine page
    return redirect(url_for('medicineManagement'))
    
# API for editing medicine
@app.route('/medicineManagement/editMedicine/<string:medicineID>', methods = ['GET','POST'])
@is_logged_in
def editMedicine(medicineID):
    # get form data
    medicineForm = MedicineForm(request.form)
    # check if request exist and form valid
    if request.method == 'POST' and medicineForm.validate():
        medicineName = medicineForm.medicineName.data
        # database connection
        cur = mysql.connection.cursor()
        result = cur.execute("SELECT * FROM medicines where medicineName = %s", [medicineName])
        # if medicine exist
        if result > 0:
            flash('Current system do not support name correction to an existing medicne','danger')
            flash('You may need to delete this wrong medicine and entry record again in the patient profile','danger')
        # if medicine not exist
        else:
            cur.execute("UPDATE medicines SET medicineName = %s WHERE medicineID = %s", [medicineName,medicineID])
            #commit
            mysql.connection.commit()
            flash('Success','success')
            # for auto-complete
            result = cur.execute("SELECT * FROM medicines")
            session['medicines'] = cur.fetchall()
        cur.close()
    else:
        flash('Invalid Form','danger')
    # jump tp manage medicine page
    return redirect(url_for('medicineManagement'))

# API for deleting medicine   
@app.route('/medicineManagement/deleteMedicine/<string:medicineID>', methods = ['GET','POST'])
@is_logged_in
def deleteMedicine(medicineID):
    # database connection
    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM medicines WHERE medicineID = %s", [medicineID])
    mysql.connection.commit()
    # for auto-complete
    result = cur.execute("SELECT * FROM medicines")
    session['medicines'] = cur.fetchall()
    cur.close()
    # jump tp manage medicine page
    return redirect(url_for('medicineManagement'))

#===========================================================================Research=================================================================#
# API for research page 
@app.route('/research', methods = ['GET','POST'])
@is_logged_in
def research():
    searchDateMedicine = SearchDateMedicine()
    searchDate = SearchDate()
    return render_template('research.html',searchDateMedicine=searchDateMedicine,searchDate=searchDate)

@app.route('/research/icuMedicines', methods = ['GET','POST'])
@is_logged_in
def icuMedicines():
    searchDateMedicine = SearchDateMedicine(request.form)
    dataset = 'empty'
    if request.method == 'POST' and searchDateMedicine.validate():
    # get accounts from database
        cur = mysql.connection.cursor()
        dateFrom = searchDateMedicine.dateFrom.data
        dateTo = searchDateMedicine.dateTo.data
        medicineName = searchDateMedicine.medicineName.data
        result = cur.execute("SELECT firstname, lastname, patients.urn, dose, frequency, route, medicineName, date \
                    FROM patients LEFT JOIN admissions ON patients.urn=admissions.urn \
                    LEFT JOIN icuAdmissions ON admissions.admissionID=icuAdmissions.admissionID \
                    LEFT JOIN mcICU ON icuAdmissions.icuAdmissionID=mcICU.icuAdmissionID \
                    LEFT JOIN mcICURecords ON mcICU.mcID=mcICURecords.mcID \
                    WHERE date >= %s AND date <= %s AND medicineName = %s", [dateFrom,dateTo,medicineName])
        if result > 0:
            dataset = cur.fetchall()
        else:
            flash('No Record','danger')
        cur.close()
    else:
        flash('Invalid Form','danger')
        return redirect(url_for('research'))
    return render_template('research_mc_results.html',dataset=dataset)

@app.route('/research/mmpMedicines', methods = ['GET','POST'])
@is_logged_in
def mmpMedicines():
    searchDateMedicine = SearchDateMedicine(request.form)
    dataset = 'empty'
    if request.method == 'POST' and searchDateMedicine.validate():
        cur = mysql.connection.cursor()
        dateFrom = searchDateMedicine.dateFrom.data
        dateTo = searchDateMedicine.dateTo.data
        medicineName = searchDateMedicine.medicineName.data
        result = cur.execute("SELECT firstname, lastname, patients.urn, dose, frequency, route, medicineName, dateFrom, dateTo \
                    FROM patients LEFT JOIN admissions ON patients.urn=admissions.urn \
                    LEFT JOIN mmpRecords ON admissions.admissionID=mmpRecords.admissionID \
                    WHERE dateFrom >= %s AND dateTo <= %s AND medicineName = %s", [dateFrom,dateTo,medicineName])
        if result > 0:
            dataset = cur.fetchall()
        else:
            flash('No Record','danger')
        cur.close()
    else:
        flash('Invalid Form','danger')
        return redirect(url_for('research'))
    return render_template('research_mmp_results.html',dataset=dataset)

@app.route('/research/mcdMedicines', methods = ['GET','POST'])
@is_logged_in
def mcdMedicines():
    searchDateMedicine = SearchDateMedicine(request.form)
    dataset = 'empty'
    if request.method == 'POST' and searchDateMedicine.validate():
    # get accounts from database
        cur = mysql.connection.cursor()
        dateFrom = searchDateMedicine.dateFrom.data
        dateTo = searchDateMedicine.dateTo.data
        medicineName = searchDateMedicine.medicineName.data
        result = cur.execute("SELECT firstname, lastname, patients.urn, dose, frequency, route, medicineName, date \
                    FROM patients LEFT JOIN admissions ON patients.urn=admissions.urn \
                    LEFT JOIN mcHospitalDischargeRecords ON admissions.admissionID=mcHospitalDischargeRecords.admissionID \
                    WHERE date >= %s AND date <= %s AND medicineName = %s", [dateFrom,dateTo,medicineName])
        if result > 0:
            dataset = cur.fetchall()
        else:
            flash('No Record','danger')
        cur.close()
    else:
        flash('Invalid Form','danger')
        return redirect(url_for('research'))
    return render_template('research_mc_results.html',dataset=dataset)

@app.route('/research/topDrugList', methods = ['GET','POST'])
@is_logged_in
def topDrugList():
    searchDate = SearchDate(request.form)
    medicines = 'empty'
    if request.method == 'POST' and searchDate.validate():
        # get accounts from database
        cur = mysql.connection.cursor()
        dateFrom = searchDate.dateFrom.data
        dateTo = searchDate.dateTo.data
        result = cur.execute("SELECT medicineName, \
                    COUNT(mcICURecordID) as quantity\
                    FROM mcICURecords \
                    WHERE mcICURecords.date >= %s AND mcICURecords.date <= %s \
                    GROUP BY medicineName \
                    ORDER BY COUNT(mcICURecordID) DESC", [dateFrom,dateTo])
        if result > 0:
            medicines = cur.fetchall()
        else:
            flash('No Record','danger')
        cur.close()
    else:
        flash('Invalid Form','danger')
        return redirect(url_for('research'))
    return render_template('research_topDrugList.html',medicines=medicines)

@app.route('/research/showAllresults', methods = ['GET','POST'])
@is_logged_in
def showAllresults():
    cur = mysql.connection.cursor()
    mcICURecords = 'empty'
    mmpRecords = 'empty'
    mcHospitalDischargeRecords = 'empty'
    result = cur.execute("SELECT firstname, lastname, patients.urn, dose, frequency, route, medicineName, date \
                    FROM patients LEFT JOIN admissions ON patients.urn=admissions.urn \
                    LEFT JOIN icuAdmissions ON admissions.admissionID=icuAdmissions.admissionID \
                    LEFT JOIN mcICU ON icuAdmissions.icuAdmissionID=mcICU.icuAdmissionID \
                    LEFT JOIN mcICURecords ON mcICU.mcID=mcICURecords.mcID")
    if result > 0:  
        mcICURecords = cur.fetchall()
    result = cur.execute("SELECT firstname, lastname, patients.urn, dose, frequency, route, medicineName, dateFrom, dateTo \
                    FROM patients LEFT JOIN admissions ON patients.urn=admissions.urn \
                    LEFT JOIN mmpRecords ON admissions.admissionID=mmpRecords.admissionID")
    if result > 0:  
        mmpRecords = cur.fetchall()
    result = cur.execute("SELECT firstname, lastname, patients.urn, dose, frequency, route, medicineName, date \
                    FROM patients LEFT JOIN admissions ON patients.urn=admissions.urn \
                    LEFT JOIN mcHospitalDischargeRecords ON admissions.admissionID=mcHospitalDischargeRecords.admissionID")
    if result > 0:  
        mcHospitalDischargeRecords = cur.fetchall()
    return render_template('research_all_results.html',mcICURecords=mcICURecords, mmpRecords=mmpRecords, mcHospitalDischargeRecords=mcHospitalDischargeRecords )
    
#========================================================================Patient Profile=================================================================#
# API for patient profile page
@app.route('/patientProfile', methods = ['GET','POST'])
@is_logged_in
def patientProfile():
    # init forms
    patientForm = PatientForm()
    admissionForm = AdmissionForm()
    searchURN = SearchURN()
    mcForm = McForm()
    # init Jinja flags
    patient = None
    admissions = None
    ICUadmissions = None
    mcICU = None
    # render patient profile page
    return render_template('patientProfile.html', patient = patient, admissions = admissions, ICUadmissions = ICUadmissions, mcICU = mcICU,
                            patientForm = patientForm, admissionForm = admissionForm, searchURN = searchURN, mcForm=mcForm)

# API for patient search bar
@app.route('/patientProfile/searchPatient', methods = ['GET','POST'])
@is_logged_in
def searchPatient():
    # get form data
    searchURN = SearchURN(request.form)
    # check if request exist and form valid
    if request.method == 'POST' and searchURN.validate():
        urn = searchURN.urn.data
        # jump to show search result API
        return redirect(url_for('showSearchResult',urn = urn))
    else:
        flash('Invalid URN','danger')
        # jump to patient profile page
        return redirect(url_for('patientProfile'))

# API for searching result
@app.route('/patientProfile/showSearchResult/<string:urn>', methods = ['GET','POST'])
@is_logged_in
def showSearchResult(urn):
    # init forms
    patientForm = PatientForm()
    admissionForm = AdmissionForm()
    searchURN = SearchURN()
    mcForm = McForm()
    # init Jinja flags
    patient = None
    admissions = None
    ICUadmissions = None
    mcICU = None
    # database connection
    cur = mysql.connection.cursor()
    result = cur.execute("SELECT * FROM patients WHERE urn = %s", [urn])
    # if patient exist
    if result > 0:
        patient = cur.fetchone()
        # session handling
        session['urn'] = urn
        # get all admissions, icu admissions, mcICU with given URN
        result = cur.execute("SELECT * FROM admissions WHERE  urn = %s", [urn]) 
        if result > 0:    
            admissions = cur.fetchall()
        result = cur.execute("SELECT * FROM icuAdmissions")
        if result > 0:
            ICUadmissions = cur.fetchall()
        result = cur.execute("SELECT * FROM mcICU")
        if result > 0:
            mcICU = cur.fetchall()  
    # if patient not exist              
    else:
        flash('Patient not found','danger')
    cur.close()
    # render patient profile page
    return render_template('patientProfile.html',patient = patient, admissions = admissions, ICUadmissions = ICUadmissions, mcICU = mcICU,mcForm=mcForm,patientForm = patientForm,searchURN=searchURN,admissionForm=admissionForm)

# API for adding patient
@app.route('/patientProfile/addPatient', methods = ['GET','POST'])
@is_logged_in
def addPatient():
    # get form data
    patientForm = PatientForm(request.form)
    # check if request exist and form valid
    if request.method == 'POST' and patientForm.validate():
        urn = patientForm.urn.data
        firstname = patientForm.firstname.data
        lastname = patientForm.lastname.data
        dateOfBirth = patientForm.dateOfBirth.data
        # database connection
        cur = mysql.connection.cursor()
        result = cur.execute("SELECT * FROM patients where urn = %s", [urn])
        # if patient exist
        if result > 0:
            flash('Patient Already Exist','danger')
        # if patient not exist
        else:
            cur.execute("INSERT INTO patients (urn, firstname, lastname, dateOfBirth) values (%s,%s,%s,%s)", [urn,firstname,lastname,dateOfBirth] )
            # commit
            mysql.connection.commit()
            flash('Success','success')
        cur.close()
    else:
        flash('Invalid Form','danger')
    # jump to patient profile page
    return redirect(url_for('patientProfile'))

# API for editing patient
@app.route('/patientProfile/editPatient/<string:urn>', methods = ['GET','POST'])
@is_logged_in
def editPatient(urn):
    # get form data
    patientForm = PatientForm(request.form)
    # check if request exist and form valid
    if request.method == 'POST' and patientForm.validate():
        new_urn = patientForm.urn.data
        firstname = patientForm.firstname.data
        lastname = patientForm.lastname.data
        dateOfBirth = patientForm.dateOfBirth.data
        # database connection
        cur = mysql.connection.cursor()
        result = cur.execute("SELECT * FROM patients where urn = %s", [new_urn])
        # if patient exist
        if result > 0:
            cur.execute("UPDATE patients SET firstname = %s, lastname = %s, dateOfBirth = %s WHERE urn = %s", [firstname,lastname,dateOfBirth,urn])
            # commit
            mysql.connection.commit()
        # if patient not exist
        else:
            cur.execute("UPDATE patients SET urn = %s, firstname = %s, lastname = %s, dateOfBirth = %s WHERE urn = %s", [new_urn,firstname,lastname,dateOfBirth,urn])
            # commit
            mysql.connection.commit()
        flash('Success','success')    
        cur.close()
    else:
        flash('Invalid Form','danger')
    # jump to show result API
    return redirect(url_for('showSearchResult',urn = new_urn))

# API for deleting patient
@app.route('/patientProfile/deletePatient/<string:urn>', methods = ['GET','POST'])
@is_logged_in
def deletePatient(urn):
    # database connection
    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM patients WHERE urn = %s", [urn])
    mysql.connection.commit()
    cur.close()
    # jump to patient profile page
    return redirect(url_for('patientProfile'))

# API for adding admission
@app.route('/patientProfile/addAdmission', methods = ['GET','POST'])
@is_logged_in
def addAdmission():
    # get form data
    admissionForm = AdmissionForm(request.form)
    # check if request exist and form valid
    if request.method == 'POST' and admissionForm.validate():
        dateFrom = admissionForm.dateFrom.data
        dateTo = admissionForm.dateTo.data
        # database connection
        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO admissions (urn, dateFrom, dateTo) values (%s,%s,%s)", [session['urn'],dateFrom,dateTo])
        # commit
        mysql.connection.commit()
        flash('Success','success')
        cur.close()
    else:
        flash('Invalid Form','danger')
    # jump to show result API
    return redirect(url_for('showSearchResult',urn = session['urn']))

# API for editing admission
@app.route('/patientProfile/editAdmission/<string:admissionID>', methods = ['GET','POST'])
@is_logged_in
def editAdmission(admissionID):
    # get form data
    admissionForm = AdmissionForm(request.form)
    # check if request exist and form valid
    if request.method == 'POST' and admissionForm.validate():
        dateFrom = admissionForm.dateFrom.data
        dateTo = admissionForm.dateTo.data
        # database connection
        cur = mysql.connection.cursor()
        cur.execute("UPDATE admissions SET dateFrom = %s, dateTo = %s WHERE admissionID = %s", [dateFrom,dateTo,admissionID])
        # commit
        mysql.connection.commit()
        flash('Success','success')
        cur.close()
    else:
        flash('Invalid Form','danger')
    # jump to show result API
    return redirect(url_for('showSearchResult',urn = session['urn']))

# API for deleting admission
@app.route('/patientProfile/deleteAdmission/<string:admissionID>', methods = ['GET','POST'])
@is_logged_in
def deleteAdmission(admissionID):
    # database connection
    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM admissions WHERE admissionID = %s", [admissionID])
    # commit
    mysql.connection.commit()
    cur.close()
    # jump to show result API
    return redirect(url_for('showSearchResult',urn = session['urn']))

# API for adding ICU admission
@app.route('/patientProfile/addICUAdmission/<string:admissionID>', methods = ['GET','POST'])
@is_logged_in
def addICUAdmission(admissionID):
    # get form data
    admissionForm = AdmissionForm(request.form)
    # check if request exist and form valid
    if request.method == 'POST' and admissionForm.validate():
        dateFrom = admissionForm.dateFrom.data
        dateTo = admissionForm.dateTo.data
        # database connection
        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO icuAdmissions (admissionID, dateFrom, dateTo) values (%s,%s,%s)", [admissionID,dateFrom,dateTo])
        # commit
        mysql.connection.commit()
        flash('Success','success')
        cur.close()
    else:
        flash('Invalid Form','danger')
    # jump to show result API
    return redirect(url_for('showSearchResult',urn = session['urn']))

# API for editing ICU admission
@app.route('/patientProfile/editICUAdmission/<string:icuAdmissionID>', methods = ['GET','POST'])
@is_logged_in
def editICUAdmission(icuAdmissionID):
    # get form data
    admissionForm = AdmissionForm(request.form)
    # check if request exist and form valid
    if request.method == 'POST' and admissionForm.validate():
        dateFrom = admissionForm.dateFrom.data
        dateTo = admissionForm.dateTo.data
        # database connection
        cur = mysql.connection.cursor()
        cur.execute("UPDATE icuAdmissions SET dateFrom = %s, dateTo = %s WHERE icuAdmissionID = %s", [dateFrom,dateTo,icuAdmissionID])
        # commit
        mysql.connection.commit()
        flash('Success','success')
        cur.close()
    else:
        flash('Invalid Form','danger')
    # jump to show result API
    return redirect(url_for('showSearchResult',urn = session['urn']))

# API for deleting ICU admission
@app.route('/patientProfile/deleteICUAdmission/<string:icuAdmissionID>', methods = ['GET','POST'])
@is_logged_in
def deleteICUAdmission(icuAdmissionID):
    # database connection
    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM icuAdmissions WHERE icuAdmissionID = %s", [icuAdmissionID])
    # commit
    mysql.connection.commit()
    cur.close()
    # jump to show result API
    return redirect(url_for('showSearchResult',urn = session['urn']))

# API for adding ICU Medication chart
@app.route('/patientProfile/addMCICU/<string:icuAdmissionID>', methods = ['GET','POST'])
@is_logged_in
def addMCICU(icuAdmissionID):
    # get form data
    mcForm = McForm(request.form)
    # check if request exist and form valid
    if request.method == 'POST' and mcForm.validate():
        dateFrom = mcForm.dateFrom.data
        dateTo = mcForm.dateTo.data
        type = mcForm.type.data
        # database connection
        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO mcICU (icuAdmissionID, dateFrom, dateTo, type) values (%s,%s,%s,%s)", [icuAdmissionID,dateFrom,dateTo,type])
        # commit
        mysql.connection.commit()
        cur.close()
    else:
        flash('Invalid Form Input','danger')
    # jump to show result API
    return redirect(url_for('showSearchResult',urn = session['urn']))

# API for editing ICU Medication chart
@app.route('/patientProfile/editMCICU/<string:mcID>', methods = ['GET','POST'])
@is_logged_in
def editMCICU(mcID):
    # get form data
    mcForm = McForm(request.form)
    # check if request exist and form valid
    if request.method == 'POST' and mcForm.validate():
        dateFrom = mcForm.dateFrom.data
        dateTo = mcForm.dateTo.data
        # database connection
        cur = mysql.connection.cursor()
        cur.execute("UPDATE mcICU SET dateFrom = %s, dateTo = %s WHERE mcID = %s", [dateFrom,dateTo,mcID])
        # commit
        mysql.connection.commit()
        cur.close()
    else:
        flash('Invalid Form Input','danger')
    # jump to show result API
    return redirect(url_for('showSearchResult',urn = session['urn']))

# API for deleting ICU Medication chart
@app.route('/patientProfile/deleteMCICU/<string:mcID>', methods = ['GET','POST'])
@is_logged_in
def deleteMCICU(mcID):
    # database connection
    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM mcICU WHERE mcID = %s", [mcID])
    # commit
    mysql.connection.commit()
    cur.close()
    # jump to show result API
    return redirect(url_for('showSearchResult',urn = session['urn']))

#===========================================================================MMP=================================================================#
# API for mmp page
@app.route('/mmp/<string:admissionID>', methods = ['GET','POST'])
@is_logged_in
def mmp(admissionID):
    # init forms
    mmpRecordForm = MmpRecordForm()
    # init Jinja flag
    mmpRecords = None
    # database connection
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM admissions where admissionID = %s", [admissionID])
    admission = cur.fetchone()
    result = cur.execute("SELECT * FROM mmpRecords where admissionID = %s", [admissionID]) # should get urn by paitent['urn'] here
    # session handling
    session['admissionID'] = admissionID
    # if mmp records exist
    if result > 0:
        mmpRecords = cur.fetchall()
    cur.close()
    # render mmp page
    return render_template('mmp.html',admission=admission, mmpRecords=mmpRecords, mmpRecordForm = mmpRecordForm)

# API for adding mmp record
@app.route('/mmp/addMmpRecord', methods = ['GET','POST'])
@is_logged_in
def addMmpRecord():
    # get form data
    mmpRecordForm = MmpRecordForm(request.form)
    # check if request exist and form valid
    if request.method == 'POST' and mmpRecordForm.validate():
        medicineName = mmpRecordForm.medicineName.data
        dose = mmpRecordForm.dose.data
        route = mmpRecordForm.route.data
        frequency = mmpRecordForm.frequency.data
        # database connection
        cur = mysql.connection.cursor()
        result = cur.execute("SELECT * FROM medicines WHERE medicineName = %s",[medicineName])
        # if medicine exist
        if result > 0:    
            cur.execute("INSERT INTO mmpRecords (admissionID, medicineName, dose,route,frequency) values (%s,%s,%s,%s,%s)", [session['admissionID'],medicineName,dose,route,frequency]) 
        # if medicine not exist, add to database
        else:
            cur.execute("INSERT INTO medicines (medicineName) values (%s)", [medicineName])
            mysql.connection.commit()
            # for auto-complete
            result = cur.execute("SELECT * FROM medicines")
            # session handling
            session['medicines'] = cur.fetchall()
            cur.execute("INSERT INTO mmpRecords (admissionID, medicineName,dose,route,frequency) values (%s,%s,%s,%s,%s)", [session['admissionID'],medicineName,dose,route,frequency]) 
        # commit
        mysql.connection.commit() 
        cur.close()
        flash('Success','success')
    else:
        flash('Invalid Form Input','danger')
    # jump to mmp page
    return redirect(url_for('mmp', admissionID = session['admissionID']))

# API for editing mmp record
@app.route('/mmp/editMmpRecord/<string:mmpRecordID>', methods = ['GET','POST'])
@is_logged_in
def editMmpRecord(mmpRecordID):
    # get form data
    mmpRecordForm = MmpRecordForm(request.form)
    # check if request exist and form valid
    if request.method == 'POST' and mmpRecordForm.validate():
        medicineName = mmpRecordForm.medicineName.data
        dose = mmpRecordForm.dose.data
        route = mmpRecordForm.route.data
        frequency = mmpRecordForm.frequency.data
        # database connection
        cur = mysql.connection.cursor()
        result = cur.execute("SELECT * FROM medicines WHERE medicineName = %s",[medicineName])
        # if medicine exist
        if result > 0:    
            cur.execute("UPDATE mmpRecords SET medicineName = %s, dose = %s, route = %s, frequency = %s WHERE mmpRecordID = %s", [medicineName,dose,route,frequency,mmpRecordID])
        # if medicine not exist, add to database
        else:
            cur.execute("INSERT INTO medicines (medicineName) values (%s)", [medicineName])
            mysql.connection.commit()
            # for auto-complete
            result = cur.execute("SELECT * FROM medicines")
            session['medicines'] = cur.fetchall()
            cur.execute("UPDATE mmpRecords SET medicineName = %s, dose = %s, route = %s, frequency = %s WHERE mmpRecordID = %s", [medicineName,dose,route,frequency,mmpRecordID])
        # commit
        mysql.connection.commit()
        cur.close()
        flash('Success','success')
    else:
        flash('Invalid Form Input','danger')
    # jump to mmp page
    return redirect(url_for('mmp', admissionID = session['admissionID']))

# API for deleting mmp record
@app.route('/mmp/deleteMmpRecord/<string:mmpRecordID>', methods = ['GET','POST'])
@is_logged_in
def deleteMmpRecord(mmpRecordID):
    # database connection
    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM mmpRecords WHERE mmpRecordID = %s", [mmpRecordID])
    # commit
    mysql.connection.commit()
    cur.close()
    # jump to mmp page
    return redirect(url_for('mmp', admissionID = session['admissionID']))

#==============================================================MC_Hospital_Discharge===========================================================================#
# API for medicine chart on hospital discharge page
@app.route('/mcd/<string:admissionID>', methods = ['GET','POST'])
@is_logged_in
def mcd(admissionID):
    # init forms
    mcRecordForm = McRecordForm()
    # init Jinja flags
    mcRecords = None
    # database connection
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM admissions where admissionID = %s", [admissionID])
    admission = cur.fetchone()
    result = cur.execute("SELECT * FROM mcHospitalDischargeRecords where admissionID = %s", [admissionID]) # should get urn by paitent['urn'] here
    # session handling
    session['admissionID'] = admissionID
    # if mc record exist
    if result > 0:
        mcRecords = cur.fetchall()
    cur.close()
    # render medicine chart page
    return render_template('mcd.html',admission=admission, mcRecords=mcRecords, mcRecordForm = mcRecordForm)

# API for adding mcd record
@app.route('/mcd/addMcdRecord', methods = ['GET','POST'])
@is_logged_in
def addMcdRecord():
    # get form data
    mcRecordForm = McRecordForm(request.form)
    # check if request exist and form valid
    if request.method == 'POST' and mcRecordForm.validate():
        medicineName = mcRecordForm.medicineName.data
        date = mcRecordForm.date.data
        dose = mcRecordForm.dose.data
        route = mcRecordForm.route.data
        frequency = mcRecordForm.frequency.data
        # database connection
        cur = mysql.connection.cursor()
        result = cur.execute("SELECT * FROM medicines WHERE medicineName = %s",[medicineName])
        # if medicine exist
        if result > 0:    
            cur.execute("INSERT INTO mcHospitalDischargeRecords (admissionID, medicineName,date, dose,route,frequency) values (%s,%s,%s,%s,%s,%s)", [session['admissionID'],medicineName,date,dose,route,frequency]) 
        # if medicine not exist, add to database
        else:
            cur.execute("INSERT INTO medicines (medicineName) values (%s)", [medicineName])
            mysql.connection.commit()
            # for auto-complete
            result = cur.execute("SELECT * FROM medicines")
            session['medicines'] = cur.fetchall()
            cur.execute("INSERT INTO mcHospitalDischargeRecords (admissionID, medicineName,date,dose,route,frequency) values (%s,%s,%s,%s,%s,%s)", [session['admissionID'],medicineName,date,dose,route,frequency]) 
        # commit
        mysql.connection.commit() 
        cur.close()
        flash('Success','success')
    else:
        flash('Invalid Form Input','danger')
    # jump to mcd page
    return redirect(url_for('mcd', admissionID = session['admissionID']))

# API for editing mcd record
@app.route('/mcd/editMcdRecord/<string:mcHDRecordID>', methods = ['GET','POST'])
@is_logged_in
def editMcdRecord(mcHDRecordID):
    # get form data
    mcRecordForm = McRecordForm(request.form)
    # check if request exist and form valid
    if request.method == 'POST' and mcRecordForm.validate():
        medicineName = mcRecordForm.medicineName.data
        date = mcRecordForm.date.data
        dose = mcRecordForm.dose.data
        route = mcRecordForm.route.data
        frequency = mcRecordForm.frequency.data
        # database connection
        cur = mysql.connection.cursor()
        result = cur.execute("SELECT * FROM medicines WHERE medicineName = %s",[medicineName])
        # if medicine exist
        if result > 0:    
            cur.execute("UPDATE mcHospitalDischargeRecords SET medicineName = %s, date=%s, dose = %s, route = %s, frequency = %s WHERE mmpRecordID = %s", [medicineName,date,dose,route,frequency,mcHDRecordID])
        # if medicine not exist
        else:
            cur.execute("INSERT INTO medicines (medicineName) values (%s)", [medicineName])
            mysql.connection.commit()
            # for auto-complete
            result = cur.execute("SELECT * FROM medicines")
            session['medicines'] = cur.fetchall()
            cur.execute("UPDATE mmpRecords SET medicineName = %s, date=%s, dose = %s, route = %s, frequency = %s WHERE mmpRecordID = %s", [medicineName,date,dose,route,frequency,mcHDRecordID])
        # commit
        mysql.connection.commit()
        cur.close()
        flash('Success','success')
    else:
        flash('Invalid Form Input','danger')
    # jump to mcd page
    return redirect(url_for('mcd', admissionID = session['admissionID']))

# API for deleting mcd record
@app.route('/mmp/deleteMcdRecord/<string:mcHDRecordID>', methods = ['GET','POST'])
@is_logged_in
def deleteMcdRecord(mcHDRecordID):
    # database connection
    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM mcHospitalDischargeRecords WHERE mcHDRecordID = %s", [mcHDRecordID])
    # commit
    mysql.connection.commit()
    cur.close()
    # jump to mcd page
    return redirect(url_for('mcd', admissionID = session['admissionID']))

#===========================================================================MC=================================================================#
# API for medicine chart of ICU admission (with customized label)
@app.route('/mc/<string:mcID>', methods = ['GET','POST'])
@is_logged_in
def mcICU(mcID):
    # init forms
    mcRecordForm = McRecordForm()
    # init Jinja flag
    mcRecords = None
    # session handling
    session['mcID'] = mcID
    # database connection
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM mcICU where mcID = %s", [mcID])
    mcICU = cur.fetchone()
    result = cur.execute("SELECT * FROM mcICURecords where mcID = %s", [mcID]) # should get urn by paitent['urn'] here
    # if mc record exist
    if result > 0:
        mcRecords = cur.fetchall()    
    cur.close()
    # render mc page
    return render_template('mc.html', mcRecords=mcRecords, mcRecordForm=mcRecordForm, mcICU=mcICU)

# API for adding mc ICU record
@app.route('/mc/addMcRecord', methods = ['GET','POST'])
@is_logged_in
def addMcRecord():
    # get form data
    mcRecordForm = McRecordForm(request.form)
    # check if request exist and form valid
    if request.method == 'POST' and mcRecordForm.validate():
        medicineName = mcRecordForm.medicineName.data
        date= mcRecordForm.date.data
        dose = mcRecordForm.dose.data
        route = mcRecordForm.route.data
        frequency = mcRecordForm.frequency.data
        # database connection
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM medicines")
        result = cur.fetchall()  
        medicineExist = False    
        for medicine in result:
            if medicine['medicineName'] == medicineName:
                medicineExist = True
        # if medicine exist
        if medicineExist == True:
            cur.execute("INSERT INTO mcICURecords (mcID, medicineName, date, dose, route, frequency) values (%s,%s,%s,%s,%s,%s)", [session['mcID'],medicineName,date,dose,route,frequency])    
        # if medicine not exist, add to database
        else:
            cur.execute("INSERT INTO medicines (medicineName) values (%s)", [medicineName])
            mysql.connection.commit()
            # for auto-complete
            result = cur.execute("SELECT * FROM medicines")
            session['medicines'] = cur.fetchall()
            cur.execute("INSERT INTO mcICURecords (mcID, medicineName, date,dose, route, frequency) values (%s,%s,%s,%s,%s,%s)", [session['mcID'],medicineName,date,dose,route,frequency])
        # commit
        mysql.connection.commit()
        cur.close()
        flash('Success','success')
    else:
        flash('Invalid Form Input','danger')
    # jump to mc ICU page
    return redirect(url_for('mcICU', mcID = session['mcID']))

# API for editing mc ICU record
@app.route('/mc/editMcRecord/<string:mcICURecordID>', methods = ['GET','POST'])
@is_logged_in
def editMcRecord(mcICURecordID):
    # get form data
    mcRecordForm = McRecordForm(request.form)
    # check if request exist and form valid
    if request.method == 'POST' and mcRecordForm.validate():
        medicineName = mcRecordForm.medicineName.data
        date = mcRecordForm.date.data
        dose = mcRecordForm.dose.data
        route = mcRecordForm.route.data
        frequency = mcRecordForm.frequency.data
        # database connection
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM medicines")
        result = cur.fetchall()
        medicineExist = False       
        for medicine in result:
            if medicine['medicineName'] == medicineName:
                medicineExist = True
        # if medicine exist
        if medicineExist == True:
            cur.execute("UPDATE mcICURecords SET medicineName = %s, date = %s, dose = %s, route = %s, frequency = %s WHERE mcICURecordID = %s", [medicineName,date,dose,route,frequency,mcICURecordID])
        # if medicine not exist
        else:
            cur.execute("INSERT INTO medicines (medicineName) values (%s)", [medicineName])
            mysql.connection.commit()
            # for auto-complete
            result = cur.execute("SELECT * FROM medicines")
            session['medicines'] = cur.fetchall()
            cur.execute("UPDATE mcICURecords SET medicineName = %s, date = %s, dose = %s, route = %s, frequency = %s WHERE mcICURecordID = %s", [medicineName,date,dose,route,frequency,mcICURecordID])
        # commit
        mysql.connection.commit()
        cur.close()
        flash('Success','success')
    else:
        flash('Invalid Form Input','danger')
    # jump to mc ICU page
    return redirect(url_for('mcICU', mcID = session['mcID']))
   
# API for deleting mc ICU record
@app.route('/mc/deleteMcRecord/<string:mcICURecordID>', methods = ['GET','POST'])
@is_logged_in
def deleteMcRecord(mcICURecordID):
    # database connection
    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM mcICURecords WHERE mcICURecordID = %s", [mcICURecordID])
    # commit
    mysql.connection.commit()
    cur.close()
    # jump to mc ICU page
    return redirect(url_for('mcICU', mcID = session['mcID']))

#============================================================================Forms=================================================================#
# specify login form
class LoginForm(Form):
    email = StringField('', [validators.Length(min=6, max=40)])  
    password = StringField('', [validators.Length(min=6, max=25)])

# specify add account form
class AddAccountForm(Form):
    email = StringField('', [validators.Length(min=6, max=40)])  
    firstname = StringField('', [validators.Length(min=2, max=25)])
    lastname = StringField('', [validators.Length(min=2, max=25)])
    staffType = SelectField('',choices=[('admin', 'admin'), ('normal', 'normal')])
    password = StringField('', [validators.Length(min=6, max=25)])

# specify edit account form
class EditAccountForm(Form):
    email = StringField('', [validators.Length(min=6, max=40)])  
    firstname = StringField('', [validators.Length(min=2, max=25)])
    lastname = StringField('', [validators.Length(min=2, max=25)])
    staffType = SelectField('',choices=[('admin', 'admin'), ('normal', 'normal')])
    password = StringField('', [validators.Length(min=6, max=25)]) 

# specify add medicine form
class MedicineForm(Form):
    medicineName = StringField('', [validators.Length(min=2, max=25)])

# specify add mmp record form
class MmpRecordForm(Form):
    medicineName = StringField('', [validators.Length(min=2, max=25)])
    dose = StringField('', [validators.Length(min=2, max=25)])
    route = SelectField('',choices=[('INH', 'INH'), ('NEB', 'NEB'), ('PO', 'PO'), 
                                    ('PV', 'PV'), ('PR', 'PR'), ('IV', 'IV'), 
                                    ('IM', 'IM'), ('Subcut', 'Subcut'), ('NG', 'NG'), 
                                    ('REY', 'REY'), ('LEY', 'LEY'), ('BEY', 'BEY'), 
                                    ('Subling', 'Subling'), ('Buccal', 'Buccal'), ('IP', 'IP'), 
                                    ('Epidural', 'Epidural'), ('Intrathecal', 'Intrathecal'), ('Nasal', 'Nasal'), 
                                    ('PEG', 'PEG'), ('Topical', 'Topical')])
    frequency = SelectField('',choices=[('Alternate days', 'Alternate days'), ('BD', 'BD'), ('MANE', 'MANE'), 
                                    ('NOCTE', 'NOCTE'), ('PRN', 'PRN'), ('QID', 'QID'), 
                                    ('Q4h', 'Q4h'), ('Q1H', 'Q1H'), ('Q2H', 'Q2H'), 
                                    ('Q3H', 'Q3H'), ('Q6H', 'Q6H'), ('Q8H', 'Q8H'), 
                                    ('STAT', 'STAT'), ('TDS', 'TDS'), ('Weekly', 'Weekly'), 
                                    ('Midday', 'Midday'), ('Twice weekly', 'Twice weekly')])

# specify mc record form
class McForm(Form):
    dateFrom = DateTimeField('',format="%Y-%m-%dT%H:%M", 
                          default=datetime.date.today(),
                          validators=[validators.DataRequired()])
    dateTo = DateTimeField('',format="%Y-%m-%dT%H:%M", 
                          default=datetime.date.today(),
                          validators=[validators.DataRequired()])
    type = StringField('', [validators.Length(min=2, max=25)])

# specify mc record form
class McRecordForm(Form):
    medicineName = StringField('', [validators.Length(min=2, max=25)])
    date =  DateTimeField('',format="%Y-%m-%dT%H:%M", 
                          default=datetime.date.today(),
                          validators=[validators.DataRequired()])
    dose = StringField('', [validators.Length(min=2, max=25)])  
    route = SelectField('',choices=[('INH', 'INH'), ('NEB', 'NEB'), ('PO', 'PO'), 
                                ('PV', 'PV'), ('PR', 'PR'), ('IV', 'IV'), 
                                ('IM', 'IM'), ('Subcut', 'Subcut'), ('NG', 'NG'), 
                                ('REY', 'REY'), ('LEY', 'LEY'), ('BEY', 'BEY'), 
                                ('Subling', 'Subling'), ('Buccal', 'Buccal'), ('IP', 'IP'), 
                                ('Epidural', 'Epidural'), ('Intrathecal', 'Intrathecal'), ('Nasal', 'Nasal'), 
                                ('PEG', 'PEG'), ('Topical', 'Topical')])
    frequency = SelectField('',choices=[('Alternate days', 'Alternate days'), ('BD', 'BD'), ('MANE', 'MANE'), 
                                ('NOCTE', 'NOCTE'), ('PRN', 'PRN'), ('QID', 'QID'), 
                                ('Q4h', 'Q4h'), ('Q1H', 'Q1H'), ('Q2H', 'Q2H'), 
                                ('Q3H', 'Q3H'), ('Q6H', 'Q6H'), ('Q8H', 'Q8H'), 
                                ('STAT', 'STAT'), ('TDS', 'TDS'), ('Weekly', 'Weekly'), 
                                ('Midday', 'Midday'), ('Twice weekly', 'Twice weekly')])

# specify add patient form
class PatientForm(Form):
    urn = StringField('', [validators.Length(min=4, max=10)])  
    firstname = StringField('', [validators.Length(min=2, max=25)])
    lastname = StringField('', [validators.Length(min=2, max=25)])
    dateOfBirth = DateField('')

# specify edit admission form
class AdmissionForm(Form):
    dateFrom = DateTimeField('',format="%Y-%m-%dT%H:%M", 
                          default=datetime.date.today(),
                          validators=[validators.DataRequired()])
    dateTo = DateTimeField('',format="%Y-%m-%dT%H:%M", 
                          default=datetime.date.today(),
                          validators=[validators.DataRequired()])

# specify search patient form
class SearchURN(Form):
    urn = StringField('', [validators.Length(min=4, max=10)])  

# specify search patient form
class SearchDateMedicine(Form):
    dateFrom = DateTimeField('',format="%Y-%m-%dT%H:%M", 
                          default=datetime.date.today(),
                          validators=[validators.DataRequired()])
    dateTo = DateTimeField('',format="%Y-%m-%dT%H:%M", 
                          default=datetime.date.today(),
                          validators=[validators.DataRequired()])
    medicineName = StringField('', [validators.Length(min=2, max=25)])

class SearchDate(Form):
    dateFrom = DateTimeField('',format="%Y-%m-%dT%H:%M", 
                          default=datetime.date.today(),
                          validators=[validators.DataRequired()])
    dateTo = DateTimeField('',format="%Y-%m-%dT%H:%M", 
                          default=datetime.date.today(),
                          validators=[validators.DataRequired()])

# main function
if __name__ == '__main__':
    app.secret_key='secret123'
    app.run(debug=True)

