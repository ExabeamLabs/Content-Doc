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
	"""({host}[\w.\-]{1,2000}) sonarw """,
	""""\$date":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)""",
        """"DB User Name":"(({db_domain}[^\\"]{1,2000})\\+)?(SYSTEM|({db_user}[^\\"]{1,2000}))""",
        """"OS User":"(({domain}[^\\"]{1,2000})\\+)?(SYSTEM|({user}[^\\"]{1,2000}))""",
	""""Server IP":"({dest_ip}[^"]{1,2000})""",
	""""Service Name":"({service_name}[^"]{1,2000})""",
	""""Server Host Name":"({dest_host}[^"]{1,2000})""",
	""""Client Host Name":"({src_host}[^"]{1,2000})""",
	""""Database Name":"({database_name}[^"]{1,2000})""",
	"""Client IP":"({src_ip}[^"]{1,2000})""",
  ]
}
```