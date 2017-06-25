import os,sys
from flask import Flask, request, redirect, url_for, abort
from werkzeug.utils import secure_filename
import uuid
import zipfile
import xml.sax
import dateutil.parser
import time
import subprocess

UPLOAD_FOLDER = '/home/phil/dev/bc/vigruzki/files'
ALLOWED_EXTENSIONS = set(['zip'])

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

class RegHandler(xml.sax.ContentHandler ):
        def __init__(self):
                self.updateTime = ""
                self.updateTimeUrgently = ""
                self.updateTime_ut = 0.0
                self.updateTimeUrgently_ut = 0.0

        # Call when an element starts
        def startElement(self, tag, attributes):
                if tag == "reg:register":
                        print(tag)
                        self.updateTime = attributes["updateTime"]
                        self.updateTimeUrgently = attributes["updateTimeUrgently"]
                        self.updateTime_ut = time.mktime(dateutil.parser.parse(self.updateTime).timetuple())
                        self.updateTimeUrgently_ut = time.mktime(dateutil.parser.parse(self.updateTimeUrgently).timetuple())


def allowed_file(filename):
        return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/', methods=['GET', 'POST'])
def upload_file():
        if request.method == 'POST':
                # check if the post request has the file part
                if 'file' not in request.files:
                        flash('No file part')
                        return redirect(request.url)
                file = request.files['file']
                # if user does not select file, browser also
                # submit a empty part without filename
                if file.filename == '':
                        flash('No selected file')
                        return redirect(request.url)
                if file and allowed_file(file.filename):
                        try:
                                H = RegHandler()
                                tempdir = os.path.join(app.config['UPLOAD_FOLDER'], str(uuid.uuid4()))
                                os.mkdir(tempdir)
                                filename = os.path.join(tempdir, 'dump.zip')
                                file.save(filename)
                                if zipfile.is_zipfile(filename):
                                        with zipfile.ZipFile(filename) as myzip:
                                                try:
                                                        info1 = myzip.getinfo('dump.xml')
                                                        info2 = myzip.getinfo('dump.xml.sig')
                                                        myxml = myzip.extract('dump.xml', tempdir)
                                                        mysig = myzip.extract('dump.xml.sig', tempdir)
                                                        tempfile = os.path.join(tempdir,'dump.xml.temp')
                                                        args = ['openssl', 'smime', '-verify', '-engine', 'gost', '-in', mysig, '-noverify', '-inform', 'DER', '-content', myxml, '-out', tempfile]
                                                        if subprocess.call(args) == 0:
                                                                parser = xml.sax.make_parser()
                                                                parser.setFeature(xml.sax.handler.feature_namespaces, 0)
                                                                parser.setContentHandler(H)
                                                                parser.parse(myxml)
                                                        else:
                                                                abort(500)
                                                        if os.path.exists(tempfile):
                                                                os.unlink(tempfile)
                                                        if os.path.exists(myxml):
                                                                os.unlink(myxml)
                                                        if os.path.exists(mysig):
                                                                os.unlink(mysig)
                                                except:
                                                        raise
                                                        abort(500)
                                        if os.path.exists(filename):
                                                os.unlink(filename)
                                        if os.path.exists(tempdir):
                                                os.rmdir(tempdir)
                                return '''
                                <!doctype html>
                                <title>OK</title>
                                <h1>OK updateTime=%s updateTimeUrgently=%s</h1>
                                ''' % (H.updateTime_ut, H.updateTimeUrgently_ut)
                        except:
                                raise
                                abort(500)
        return '''
        <!doctype html>
        <title>Upload new File</title>
        <h1>Upload new File</h1>
        <form method=post enctype=multipart/form-data>
                <p><input type=file name=file>
                <input type=submit value=Upload>
        </form>
    '''

if __name__ == '__main__':
    app.run(debug=True)

