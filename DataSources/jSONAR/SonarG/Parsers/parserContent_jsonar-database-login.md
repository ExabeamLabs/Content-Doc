#### Parser Content
```Java
{
Name = jsonar-database-login
  Vendor = jSONAR
  Product = SonarG
  Lms = Direct
  DataType = "database-login"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """ sonarw """, """"$date":""", """"OS User":""", """"Database Name":""" ]
  Fields = [
	"""({host}[\w.\-]+) sonarw """,
	""""\$date":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)""",
        """"DB User Name":"(({db_domain}[^\\"]+)\\+)?(SYSTEM|({db_user}[^\\"]+))""",
        """"OS User":"(({domain}[^\\"]+)\\+)?(SYSTEM|({user}[^\\"]+))""",
	""""Server IP":"({dest_ip}[^"]+)""",
	""""Service Name":"({service_name}[^"]+)""",
	""""Server Host Name":"({dest_host}[^"]+)""",
	""""Client Host Name":"({src_host}[^"]+)""",
	""""Database Name":"({database_name}[^"]+)""",
	"""Client IP":"({src_ip}[^"]+)""",
  ]
}
```