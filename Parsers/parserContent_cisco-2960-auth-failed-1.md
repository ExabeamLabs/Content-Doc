#### Parser Content
```Java
{
Name = cisco-2960-auth-failed-1
  DataType = "authentication-failed"
  Conditions = [ """%DOT1X-5-FAIL:""", """Authentication failed""" ]
}

{
  Name = n-forwarded-cef-nac-logon
  Vendor = Cisco
  Product = Cisco ISE
  Lms = NitroCefSyslog
  DataType = "nac-logon"
  TimeFormat = "epoch"
  Conditions = [ "|McAfee|ESM", "|268-2146859015|"]
  Fields = [
    """\srt=({time}\d+)""",
    """deviceTranslatedAddress=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """src=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """suser=({user}.+?)\s+nitroSensor_Name""",
    """nitroSensor_Name=({auth_server}[^\s]+)"""
  ]
}
```