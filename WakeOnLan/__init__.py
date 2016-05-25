from flask import Flask, request, redirect, url_for, render_template, flash
from flask_bootstrap import Bootstrap
from flask_appconfig import AppConfig
from flask_wtf import Form, RecaptchaField
from flask_wtf.file import FileField
from wtforms import TextField, HiddenField, ValidationError, RadioField,\
    BooleanField, SubmitField, IntegerField, FormField, validators, PasswordField
from wtforms.validators import Required, IPAddress, MacAddress

from flask.ext.login import LoginManager, UserMixin, login_required, login_user, logout_user, current_user

#from flask_blitzdb import BlitzDB
from blitzdb import FileBackend, Document


import pyping
from wakeonlan import wol

class Device(Document):
    pass

#
class User(UserMixin):
    user_database = { "arnaudco" : ("arnaudco","arnaud")}

    def __init__(self, username, password):
        self.id = username
        self.password = password

    @classmethod
    def getById(cls, id):
        return cls.user_database.get(id)

    @classmethod
    def get(cls, id, passw):
        username, password = cls.user_database.get(id)

        if username == id and password == passw:
            return cls.user_database.get(id)
        else:
            return None

    def is_autheticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return self.id

    def __repr__(self):
        return '<User %r>' % (self.id)




# straight from the wtforms docs:
class LoginForm(Form):
    username = TextField('Username', validators=[Required()])
    password = PasswordField('Password',validators=[Required()])
    submit_button = SubmitField('Login')

class AddDeviceForm(Form):
    name = TextField('Name', validators=[Required()])
    mac = TextField('MAC', validators=[Required(), MacAddress()])
    ip = TextField('IP', validators=[Required(), IPAddress()])

    submit_button = SubmitField('Add')

    # def validate(self):
    #     if not super(AddDeviceForm, self).validate():
    #         return False
    #     if not self.ip.data and not self.mac.data:
    #         msg = 'Check field format'
    #         self.ip.errors.append(msg)
    #         self.mac.errors.append(msg)
    #         raise ValidationError(msg)
    #         return False
    #     return True



class TelephoneForm(Form):
    country_code = IntegerField('Country Code', [validators.required()])
    area_code = IntegerField('Area Code/Exchange', [validators.required()])
    number = TextField('Number')


class ExampleForm(Form):
    field1 = TextField('First Field', description='This is field one.')
    field2 = TextField('Second Field', description='This is field two.',
                       validators=[Required()])
    hidden_field = HiddenField('You cannot see this', description='Nope')
    recaptcha = RecaptchaField('A sample recaptcha field')
    radio_field = RadioField('This is a radio field', choices=[
        ('head_radio', 'Head radio'),
        ('radio_76fm', "Radio '76 FM"),
        ('lips_106', 'Lips 106'),
        ('wctr', 'WCTR'),
    ])
    checkbox_field = BooleanField('This is a checkbox',
                                  description='Checkboxes can be tricky.')

    # subforms
    mobile_phone = FormField(TelephoneForm)

    # you can change the label as well
    office_phone = FormField(TelephoneForm, label='Your office phone')

    ff = FileField('Sample upload')

    submit_button = SubmitField('Submit Form')


    def validate_hidden_field(form, field):
        raise ValidationError('Always wrong')



def pingDeviceByIp(ip):
    r = pyping.ping(ip)
    return r.ret_code


def wolDeviceByMac(mac):
    try:
        wol.send_magic_packet(mac)
    except:
        pass


def create_app(configfile=None):
    app = Flask(__name__)
    AppConfig(app, configfile)  # Flask-Appconfig is not necessary, but
                                # highly recommend =)
                                # https://github.com/mbr/flask-appconfig
    Bootstrap(app)

    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view='login'


    #NoSQL Backend
    backend = FileBackend("/tmp/wakeonlan.db")
    backend.create_index(Device, fields={'id':1}, unique=True)
    
    #TEST Devices
    alldevices = backend.filter(Device, {})
    if len(alldevices) == 0 :
        try:
            pc1 = Device({"id" : "001122334411", "name" : "PC 1", "mac" : "00:11:22:33:44:11", "ip":"192.168.222.111", 'status' : ''})
            backend.save(pc1)
            pc2 = Device({"id" : "001122334422","name" : "PC 2", "mac" : "00:11:22:33:44:22", "ip":"192.168.222.112", 'status' : ''})
            backend.save(pc2)
            pc3 = Device({"id" : "001122334433","name" : "Router", "mac" : "00:11:22:33:44:33", "ip":"192.168.222.1", 'status' : ''})
            backend.save(pc3)
            backend.commit()
        except: 
            backend.revert()
            pass

    # in a real app, these should be configured through Flask-Appconfig
    app.config['SECRET_KEY'] = 'devkey'
    # app.config['RECAPTCHA_PUBLIC_KEY'] = \
    #     '6Lfol9cSAAAAADAkodaYl9wvQCwBMr3qGR_PPHcw'

    def getDeviceById(id):
        device = None
        try:
            device = backend.get(Device, {'id':id})
        except:
            pass

        return device

    def pingDeviceById(id):
        #Get Device
        device = backend.get(Device, {'id':id})

        if device:
            #Get Device's IP
            ip = device['ip']
            result = pingDeviceByIp(ip)

            #Update Status   UP/Down/''
            if result==0:
                device['status'] = 'UP'
            else:
                device['status'] = 'DOWN'

            backend.save(device)
            return result

        return None

    def wolDeviceById(id):
        #Get Device
        device = backend.get(Device, {'id':id})

        if device:
            #WoL for Device MAC
            mac = device['mac']
            wolDeviceByMac(mac)

        return None

    @login_manager.user_loader
    def user_loader(user_id):
        """Given *user_id*, return the associated User object.
        :param unicode user_id: user_id (email) user to retrieve
        """
        user_entry = User.getById(user_id)
        if user_entry is not None:
            user = User(user_entry[0], user_entry[1])
            return user
        else:
            return None

    @app.route('/', methods=('GET', 'POST'))
    @login_required
    def index():
        form = ExampleForm()
        form.validate_on_submit()  # to get error messages to the browser
        # flash('critical message', 'critical')
        # flash('error message', 'error')
        # flash('warning message', 'warning')
        # flash('info message', 'info')
        # flash('debug message', 'debug')
        # flash('different message', 'different')
        # flash('uncategorized message')
        alldevices = None
        alldevices = backend.filter(Device, {}).sort('name')

        #app.logger.info('Devices: %s' % (len(alldevices) ) )

        return render_template('index.html', form=form, devices = alldevices)

    @app.route('/login', methods=('GET', 'POST'))
    def login():
        if request.method == 'GET':
            form = LoginForm()
            form.validate_on_submit()  # to get error messages to the browser
            return render_template('login.html', form=form)

        username = request.form['username']
        password = request.form['password']

        user_entry = User.get(username, password)
        if user_entry is None:
            flash('Username or Passord is invalid', 'error')
            return redirect(url_for('login'))

        user = User(user_entry[0], user_entry[1])
        login_user(user, remember=True)
        return redirect(request.args.get('next') or url_for('index'))


    @app.route("/logout", methods=["GET"])
    @login_required
    def logout():
        """Logout the current user."""
        user = current_user
        user.authenticated = False
        logout_user()
        return redirect(url_for('login'))



    @app.route('/addDevice', methods=('GET', 'POST'))
    @login_required
    def addDevice():
        if request.method == 'GET':
            form = AddDeviceForm()
            form.validate_on_submit()  # to get error messages to the browser
            return render_template('add_device.html', form=form)

        name = request.form['name']
        mac = request.form['mac']
        ip = request.form['ip']
        id = mac.replace(':','')

        try:
            newDevice = Device({"id" : id, "name" : name, "mac" : mac, "ip":ip, 'status' : ''})
            backend.save(newDevice)
            backend.commit()
        except:
            flash('Error creating new Device', 'error')
            pass

        return redirect(url_for('index'))


    @app.route('/editListDevice', methods=('GET', 'POST'))
    @login_required
    def editListDevice():
        alldevices = None
        alldevices = backend.filter(Device, {}).sort('name')

        return render_template('list_device.html', devices = alldevices)



    @app.route('/pingDevice/<deviceId>', methods=('GET', 'POST'))
    @login_required
    def pingDevice(deviceId):
        app.logger.info('pingDevice: %s' % (deviceId ) )
        device = getDeviceById(deviceId)
        result = pingDeviceById(deviceId)

        app.logger.info('pingDevice: %s' % (result ) )

        if result == 0:
            flash('Device %s is UP' % (device['name']), 'info')
        else:
            flash('Device %s is DOWN' % (device['name']), 'error')

        return redirect(url_for('index'))


    @app.route('/wolDevice/<deviceId>', methods=('GET', 'POST'))
    @login_required
    def wolDevice(deviceId):
        app.logger.info('wolDevice: %s' % (deviceId ) )
        device = getDeviceById(deviceId)
        result = wolDeviceById(deviceId)

        if device:
            flash('WoL sent to %s' % (device['name']), 'info')
        else:
            flash('WoL error', 'error')

        return redirect(url_for('index'))


    @app.route('/deleteDevice/<deviceId>', methods=('GET', 'POST'))
    @login_required
    def deleteDevice(deviceId):
        app.logger.info('wolDevice: %s' % (deviceId ) )
        device = getDeviceById(deviceId)

        try:
            backend.delete(device)
            backend.commit()
            flash('%s Deleted' % (device['name']), 'info')
        except:
            flash('Delete error', 'error')
            pass

        return redirect(url_for('editListDevice'))


    return app

if __name__ == '__main__':
    create_app().run(debug=True)
