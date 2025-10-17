import xml.etree.ElementTree as ET
from xml.dom import minidom
import xml.sax
from lxml import etree
from flask import Flask, request
import defusedxml.ElementTree as DefusedET

app = Flask(__name__)

# XXE vulnerability #1: xml.etree.ElementTree
@app.route('/parse_xml_et')
def parse_xml_et():
    xml_data = request.data.decode('utf-8')

    # Vulnerable: xml.etree.ElementTree is vulnerable to XXE
    root = ET.fromstring(xml_data)
    return f"Parsed XML: {root.tag}"

# XXE vulnerability #2: xml.dom.minidom
@app.route('/parse_xml_minidom')
def parse_xml_minidom():
    xml_data = request.data.decode('utf-8')

    # Vulnerable: minidom is vulnerable to XXE
    doc = minidom.parseString(xml_data)
    return f"Document element: {doc.documentElement.tagName}"

# XXE vulnerability #3: xml.sax
class VulnerableHandler(xml.sax.ContentHandler):
    def startElement(self, name, attrs):
        self.current_element = name

@app.route('/parse_xml_sax')
def parse_xml_sax():
    xml_data = request.data.decode('utf-8')

    # Vulnerable: xml.sax with default settings
    parser = xml.sax.make_parser()
    handler = VulnerableHandler()
    parser.setContentHandler(handler)
    parser.parseString(xml_data)

    return "XML parsed with SAX"

# XXE vulnerability #4: lxml with vulnerable settings
@app.route('/parse_xml_lxml')
def parse_xml_lxml():
    xml_data = request.data.decode('utf-8')

    # Vulnerable: lxml parser without disabling external entities
    parser = etree.XMLParser(resolve_entities=True, load_dtd=True)
    root = etree.fromstring(xml_data.encode(), parser)

    return f"Parsed with lxml: {root.tag}"

# Additional XXE pattern
def parse_user_config(xml_file_path):
    # Vulnerable: parsing external XML files
    tree = ET.parse(xml_file_path)
    root = tree.getroot()
    return root

if __name__ == '__main__':
    app.run(debug=False)