#### Parser Content
```Java
{
Name = cisco-nac-logon-2
  Vendor = Cisco
  Product = Cisco ISE
  Lms = Direct
  DataType = "nac-logon"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """, AD-User-Resolved-Identities=""", """, NetworkDeviceProfileName=""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """,\s{0,100}AD-User-SamAccount-Name=({user}[^\s,]+)""",
    """,\s{0,100}AD-User-Resolved-Identities=({user_email}[^\s,@]+@[^\s,@]+)""",
    """,\s{0,100}AD-User-Join-Point=({domain}[^\s,]+)""",
    """,\s{0,100}AuthenticationStatus=({outcome}[^,]+)""",
    """,\s{0,100}NetworkDeviceProfileName=({network}[^,]+)""",
    """,\s{0,100}Location=Location#All Locations#({location}[^,]+)""",
    """,\s{0,100}EndPointMACAddress=({mac_addrress}[^\s,]+)""",
    """, AuthenticationMethod=({auth_type}[^,\s]+)"""
  ]
}
```