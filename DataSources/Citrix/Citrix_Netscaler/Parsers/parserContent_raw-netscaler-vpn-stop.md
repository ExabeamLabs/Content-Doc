#### Parser Content
```Java
{
Name = raw-netscaler-vpn-stop
  Vendor = Citrix
  Product = Citrix Netscaler
  Lms = Direct
  DataType = "vpn-end"
  TimeFormat = "MM/dd/yyyy:HH:mm:ss"
  Conditions = [ "SSLVPN LOGOUT", " Client_ip " ]
  Fields = [ 
    """exabeam_host=(.+?@\s{0,100})?({host}[^\s]+)""",
   """\w+\s{1,100}\d{1,100}\s{1,100}\d\d:\d\d:\d\d\s{1,100}({host}[\w\-.]+)""",
    """exabeam_host=(.+?@\s{0,100})?(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[^\s]+))""",
    """({time}\d\d/\d\d/\d\d\d\d:\d\d:\d\d:\d\d)""",
    """User ({user_email}[^@\s]+@[^@\s]+) - Client_ip ({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """User ({user}[^@\s]+) - Client_ip ({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """ Nat_ip ({src_translated_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """ SSLVPN_client_type ({vpn_client_type}[^\s]+) -"""]
}
```