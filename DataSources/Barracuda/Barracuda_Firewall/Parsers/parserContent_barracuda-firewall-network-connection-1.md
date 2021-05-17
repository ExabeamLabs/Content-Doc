#### Parser Content
```Java
{
Name = barracuda-firewall-network-connection-1
  Vendor = Barracuda
  Product = Barracuda Firewall
  Lms = Direct
  DataType = "network-connection"
  TimeFormat = "yyyy MM dd HH:mm:ss"
  Conditions = [ """type=""", """|proto=""", """srcIF=""", """|dstService=""", """|dstIF=""", """|srcNAT=""", """|dstNAT=""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """({time}\d{1,100} \d{1,100} \d{1,100} \d{1,100}:\d{1,100}:\d{1,100})""",
    """\s{1,100}({action}\w+):\s{1,100}type=""",
    """\s{1,100}type=({event_code}[^\|]{1,2000})\|proto=""",
    """proto=({protocol}[^\|]{1,2000})""",
    """srcIF=({src_interface}[^\|]{1,2000})""",
    """srcIP=(0.0.0.0|({src_ip}[^\|]{1,2000}))""",
    """srcPort=({src_port}[^\|]{1,2000})""",
    """srcMAC=({src_mac}[^\|]{1,2000})""",
    """dstIP=(0.0.0.0|({dest_ip}[^\|]{1,2000}))""",
    """dstPort=({dest_port}[^\|]{1,2000})""",
    """dstIF=({dest_interface}[^\|]{1,2000})""",
    """rule=({rule}[^\|]{1,2000})""",
    """srcNAT=(0.0.0.0|({src_translated_ip}[^\|]{1,2000}))""",
    """dstNAT=(0.0.0.0|({dest_external_ip}[^\|]{1,2000}))""",
    """duration=({duration}[^\|]{1,2000})""",
    """receivedBytes=({bytes_in}[^\|]{1,2000})""",
    """sentBytes=({bytes_out}[^\|]{1,2000})""",
    """user=((NT AUTHORITY|({domain}[^\\]{1,2000}))\\+)?(SYSTEM|({user}[^\|]{1,2000}))""",
    """application=({app}[^\|]{1,2000})"""
   ]
}
```