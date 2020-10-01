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
    """time="({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)".*vpn=({host}[^\s]+).*user=(({user_email}[^@\s\/]+@[^@\s\/]+)|({user}[^\/\s]+)).*realm="({realm}[^"]+)?".*roles="({role}[^"]+)?".*Removed username (((({target_domain}[^\\]+)\\)?({target_user}[^\\\s]+)))"""
  ]
}
```