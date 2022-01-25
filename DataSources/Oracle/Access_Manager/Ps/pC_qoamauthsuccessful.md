#### Parser Content
```Java
{
Name = q-oam-auth-successful
  DataType = "authentication-successful"
  Conditions = [ """ IAU_RESOURCEHOST: """", """IAU_USERID: """", """ IAU_EVENTTYPE: "Authentication""""  ]

oam-app-activity = {
  Vendor = Oracle
  Product = Access Manager
  Lms = QRadar
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d[\+\-]\d\d:\d\d) ({host}[\w\-.]{1,2000})""",
    """IAU_USERID: "(null|Anonymous|GET_HIDE_COLUMN_LIST|({user}[^\s"@]{1,2000}))"""",
    """IAU_USERID: "(null|Anonymous|({user_email}[^\s"@]{1,2000}@[^\s"@]{1,2000}))"""",
    """IAU_IDENTITYDOMAIN: "(null|({domain}[^\s"]{1,2000}))"""",
    """IAU_INSTANCENAME: "(null|({target}[^"]{1,2000}))"""",
    """IAU_REMOTEIP: "({src_ip}[A-Fa-f:\d.]{1,2000})"""",
    """IAU_CLIENTIPADDRESS: "({src_ip}[A-Fa-f:\d.]{1,2000})"""",
    """IAU_RESOURCEHOST: "(null|login|({app}[^"]{1,2000}))"""",
    """IAU_EVENTTYPE: "(null|({activity}[^"]{1,2000}))"""",
    """IAU_RESOURCEURI: "(null|({additional_info}[^"]{1,2000}))"""",
    """IAU_AUTHENTICATIONPOLICYID: "(null|({object}[^"]{1,2000}))"""",
    """IAU_AUTHORIZATIONPOLICYID: "(null|({object}[^"]{1,2000}))"""",
    """IAU_RESOURCEID: "(null|({resource}[^"]{1,2000}))"""",
  
}
```