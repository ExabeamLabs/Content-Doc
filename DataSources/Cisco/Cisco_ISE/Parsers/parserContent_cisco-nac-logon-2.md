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
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """,\s*AD-User-SamAccount-Name=({user}[^\s,]+)""",
    """,\s*AD-User-Resolved-Identities=({user_email}[^\s,@]+@[^\s,@]+)""",
    """,\s*AD-User-Join-Point=({domain}[^\s,]+)""",
    """,\s*AuthenticationStatus=({outcome}[^,]+)""",
    """,\s*NetworkDeviceProfileName=({network}[^,]+)""",
    """,\s*Location=Location#All Locations#({location}[^,]+)""",
    """,\s*EndPointMACAddress=({mac_addrress}[^\s,]+)""",
  ]
}
```