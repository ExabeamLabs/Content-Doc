#### Parser Content
```Java
{
Name = cef-cisco-firepower-dns-query
  DataType = "dns-query"
  Conditions = [ """|Cisco|""" , """|Firepower|""","""|CONNECTION STATISTICS|""", """destinationDnsDomain=""" ]
  Fields = ${CiscoParsersTemplates.cisco-firepower-events.Fields}[
  """destinationDnsDomain=({query}[^\s]+)""",
  """destinationDnsDomain=({query}[^\s]+\.({top_query}\w+\.(?i)(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za)))""",
  ]
}
cisco-firepower-events = {
  Vendor = Cisco
  Product = Cisco Firepower
  Lms = Direct
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Fields = [
    """@timestamp[":]*({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d\d\dZ)""",
    """"host[":]*({host}[^"]+)""",
    """act=({action}[^\s]+)""",
    """reason=(?:N\/A|({failure_reason}[^\s]+))""",
    """deviceInboundInterface=({src_interface}[^\s]+)\s{0,100}deviceOutboundInterface=({dest_interface}[^\s]+)""",
    """app=(?:Unknown|({app}[^\s]+))""",
    """bytesIn=({bytes_in}\d{1,100})\s{0,100}bytesOut=({bytes_out}\d{1,100})""",
    """proto=({protocol}[^\s]+)""",
    """cs1=({policy}[^\s]+)""",
    """cs2=({rule}[^\s]+)""",
    """cs5Label=({category}[^\s]+)""",
    """dpt=({dest_port}\d{1,100})\s{0,100}dst=({dest_ip}[A-Fa-f:\d.]+)""",
    """request=({url}[^\s]+)""",
    """spt=({src_port}\d{1,100})\s{0,100}src=({src_ip}[A-Fa-f:\d.]+)""",
    """user=(?:No Authentication Required|({user}[^"\s]+))""",
        ]

```