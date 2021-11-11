#### Parser Content
```Java
{
Name = cef-aruba-nac-logon-4
  Vendor = HP
  Product = Aruba ClearPass Access Control and Policy Management
  Lms = Splunk
  DataType = "nac-logon"
  TimeFormat = "yyyy-MM-dd HH:mm:ssZ"
  Conditions = [ """"ttam_category":"network/clearpass/""","""Error-Code""","""Auth-Source""" ]
  Fields = [
    """Common\.Request-Timestamp\\=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d[+-]\d{1,100})""",
    """"host":"({host}[^"]{1,2000})"""",
    """Common\.Username\\=(({user_type}host)\/)?(({domain}[^\/]{1,2000})\/)?({user_email}[^@]{1,2000}@[^,]{1,2000})?(backup|({user}[^,]{1,2000})?)(,\w+\.\w+\\=)""",
    """Common\.Service(\\)?=({network}[^=]{1,2000}?),\w+\.\w+(\\)?=""",
    """Common\.Host-MAC-Address(\\)?=({src_mac}[^,]{1,2000})""",
    """Common\.NAS-IP-Address(\\)?=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """RADIUS\.Auth-Method(\\)?=({auth_method}[^,]{1,2000})""",
    """Error-Code\\=({outcome}\d{1,100})""",
    """({event_name}(?i)auth)""",
  ]
  DupFields = [ "host->auth_server" ]
}
}
```