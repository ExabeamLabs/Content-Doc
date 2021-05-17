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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """,\s{0,100}AD-User-SamAccount-Name=({user}[^\s,]{1,2000})""",
    """,\s{0,100}AD-User-Resolved-Identities=({user_email}[^\s,@]{1,2000}@[^\s,@]{1,2000})""",
    """,\s{0,100}AD-User-Join-Point=({domain}[^\s,]{1,2000})""",
    """,\s{0,100}AuthenticationStatus=({outcome}[^,]{1,2000})""",
    """,\s{0,100}NetworkDeviceProfileName=({network}[^,]{1,2000})""",
    """,\s{0,100}Location=Location#All Locations#({location}[^,]{1,2000})""",
    """,\s{0,100}EndPointMACAddress=({mac_addrress}[^\s,]{1,2000})""",
    """, AuthenticationMethod=({auth_type}[^,\s]{1,2000})"""
  ]
}
```