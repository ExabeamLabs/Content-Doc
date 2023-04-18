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
	"""exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[\w\-.]{1,2000})""",
	"""sip\\=({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\s""",
	"""start\\=({time}\d{1,100})""",
	"""src\\=({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\s""",
	"""sourceServiceName\\=({web_domain}.+?)\s{1,100}(\w+=|$)""",
	"""act\\=({action}[A-Z_]{1,2000})\s""",		
	"""requestClientApplication\\=({user_agent}.+?)\s{1,100}(\w+\\=|$)""",
	"""cn1\\=({result_code}\d{1,100})\s""",
	"""cpt\\=({src_port}\d{1,100})\s""",
	"""spt\\=({dest_port}\d{1,100})\s""",
	"""app\\=({protocol}[^|\s]{1,2000})\s""",
	"""request\\=({uri_path}[^\s]{1,2000})\s""",
	"""qstr\\=({uri_query}[^|]{1,2000})\\\\=""",
	"""in\\=({bytes}\d{1,100}|$)\s""",
  ]

  DupFields = [ "uri_path ->full_url" ]


}
```