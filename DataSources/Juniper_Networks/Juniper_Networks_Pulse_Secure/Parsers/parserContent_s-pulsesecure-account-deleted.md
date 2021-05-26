#### Parser Content
```Java
{
Name = s-pulsesecure-account-deleted
  Vendor = Juniper Networks
  Product = Juniper Networks Pulse Secure
  Lms = Splunk
  DataType = "account-deleted"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """PulseSecure:""", """User Accounts modified.""", """id=firewall""" ]
  Fields = [
    """time="({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)".*vpn=({host}[^\s]{1,2000}).*user=(({user_email}[^@\s\/]{1,2000}@[^@\s\/]{1,2000})|({user}[^\/\s]{1,2000})).*realm="({realm}[^"]{1,2000})?".*roles="({role}[^"]{1,2000})?".*Removed username (((({target_domain}[^\\]{1,2000})\\)?({target_user}[^\\\s]{1,2000})))"""
  ]
}
```