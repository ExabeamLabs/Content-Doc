#### Parser Content
```Java
{
Name = cef-cisco-firepower-dns-query
  DataType = "dns-query"
  Conditions = [ """|Cisco|""" , """|Firepower|""","""|CONNECTION STATISTICS|""", """destinationDnsDomain=""" ]
  Fields = ${CiscoParsersTemplates.cisco-firepower-events.Fields}[
  """destinationDnsDomain=({query}[^\s]{1,2000})""",
  """destinationDnsDomain=({query}[^\s]{1,2000}\.({top_query}\w+\.(?i)(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za)))""",
  ]
}
cisco-firepower-events = {
  Vendor = Cisco
  Product = Cisco Firepower
  Lms = Direct
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Fields = [
    """@timestamp[":]{0,2000}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d\d\dZ)""",
    """"host[":]{0,2000}({host}[^"]{1,2000})""",
    """act=({action}[^\s]{1,2000})""",
    """reason=(?:N\/A|({failure_reason}[^\s]{1,2000}))""",
    """deviceInboundInterface=({src_interface}[^\s]{1,2000})\s{0,100}deviceOutboundInterface=({dest_interface}[^\s]{1,2000})""",
    """app=(?:Unknown|({app}[^\s]{1,2000}))""",
    """bytesIn=({bytes_in}\d{1,100})\s{0,100}bytesOut=({bytes_out}\d{1,100})""",
    """proto=({protocol}[^\s]{1,2000})""",
    """cs1=({policy}[^\s]{1,2000})""",
    """cs2=({rule}[^\s]{1,2000})""",
    """cs5Label=({category}[^\s]{1,2000})""",
    """dpt=({dest_port}\d{1,100})\s{0,100}dst=({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """request=({url}[^\s]{1,2000})""",
    """spt=({src_port}\d{1,100})\s{0,100}src=({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """user=(?:No Authentication Required|({user}[^"\s]{1,2000}))""",
        ]

```