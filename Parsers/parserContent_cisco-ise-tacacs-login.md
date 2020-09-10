#### Parser Content
```Java
{
Name = cisco-ise-tacacs-login
  Vendor = Cisco
  Product = Cisco ISE
  Lms = Direct
  DataType = "remote-logon"
  TimeFormat = "epoch"
  Conditions = [ """|TACACS+ Accounting""", """cat=Tacacs-Accounting""" , """ad.Service=Login"""]
  Fields = [
    """exabeam_time=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[^\s]+)""",
    """\Wrt=({time}\d+)""",
    """ad.NetworkDeviceName=({dest_host}[^\s]+)""",
    """CmdAV\\=({command}.+?)\s\]""",
    """ad.User=({user}[^\s]+)""",
    """ad.Device_,IP_,Address=({src_ip}[A-Fa-f:\d.]+)""",
    """({app}TACACS)""",
    """ad.Privilege-Level=({privileges}\d+)""",
    """ad.Remote-Address=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""
        ]
}
```