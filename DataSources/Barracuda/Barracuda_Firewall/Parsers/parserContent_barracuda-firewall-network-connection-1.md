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
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """({time}\d{1,100} \d{1,100} \d{1,100} \d{1,100}:\d{1,100}:\d{1,100})""",
    """\s{1,100}({action}\w+):\s{1,100}type=""",
    """\s{1,100}type=({event_code}[^\|]+)\|proto=""",
    """proto=({protocol}[^\|]+)""",
    """srcIF=({src_interface}[^\|]+)""",
    """srcIP=(0.0.0.0|({src_ip}[^\|]+))""",
    """srcPort=({src_port}[^\|]+)""",
    """srcMAC=({src_mac}[^\|]+)""",
    """dstIP=(0.0.0.0|({dest_ip}[^\|]+))""",
    """dstPort=({dest_port}[^\|]+)""",
    """dstIF=({dest_interface}[^\|]+)""",
    """rule=({rule}[^\|]+)""",
    """srcNAT=(0.0.0.0|({src_translated_ip}[^\|]+))""",
    """dstNAT=(0.0.0.0|({dest_external_ip}[^\|]+))""",
    """duration=({duration}[^\|]+)""",
    """receivedBytes=({bytes_in}[^\|]+)""",
    """sentBytes=({bytes_out}[^\|]+)""",
    """user=((NT AUTHORITY|({domain}[^\\]+))\\+)?(SYSTEM|({user}[^\|]+))""",
    """application=({app}[^\|]+)"""
   ]
}
```