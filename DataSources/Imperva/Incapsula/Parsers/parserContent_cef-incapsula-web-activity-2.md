#### Parser Content
```Java
{
Name = cef-incapsula-web-activity-2
  Vendor = Imperva
  Product = Incapsula
  Lms = Splunk
  DataType = "web-activity"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|Incapsula|SIEMintegration|""", """deviceExternalId""", """ ccode""" ]
  Fields = [
	"""exabeam_host=([^=]+@\s{0,100})?({host}[\w\-.]+)""",
	"""sip\\=({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\s""",
	"""start\\=({time}\d{1,100})""",
	"""src\\=({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\s""",
	"""sourceServiceName\\=({web_domain}([^\s]+\.)?({top_domain}[^\s]+\.[^\s]+)?)\s""",
	"""act\\=({action}[A-Z_]+)\s""",		
	"""requestClientApplication\\=({user_agent}.+?)\s{1,100}(\w+\\=|$)""",
	"""cn1\\=({result_code}\d{1,100})\s""",
	"""cpt\\=({src_port}\d{1,100})\s""",
	"""spt\\=({dest_port}\d{1,100})\s""",
	"""app\\=({protocol}[^|\s]+)\s""",
	"""request\\=({uri_path}[^\s]+)\s""",
	"""qstr\\=({uri_query}[^|]+)\\\\=""",
	"""in\\=({bytes}\d{1,100}|$)\s""",
	"""dproc\\=({browser}.+?)\s{1,100}(\w+\\=|$)"""
  ]

  DupFields = [ "uri_path ->full_url" ]
}
```