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
    """exabeam_host=({host}[^\s]{1,2000})""",
    """\Wrt=({time}\d{1,100})""",
    """ad.NetworkDeviceName =({dest_host}[^\s]{1,2000})""",
    """CmdAV\\=({command}.+?)\s\]""",
    """ad.User=({user}[^\s]{1,2000})""",
    """ad.Device_,IP_,Address=({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """({app}TACACS)""",
    """ad.Privilege-Level=({privileges}\d{1,100})""",
    """ad.Remote-Address=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""
        ]


}
```