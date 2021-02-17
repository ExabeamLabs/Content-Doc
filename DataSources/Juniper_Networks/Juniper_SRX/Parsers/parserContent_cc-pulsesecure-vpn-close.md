#### Parser Content
```Java
{
Name = cc-pulsesecure-vpn-close
  DataType = "vpn-end"
  Conditions = [ """CEF:""", """|Skyformation|SkyFormation Cloud Apps Security|""", """"PulseSecure:"""", """ Closed connection to """, """ bytes read """, """ bytes written """ ]
  Fields = ${JuniperParserTemplates.cef-pulsesecure-vpn-events.Fields} [
    """Closed connection to (?:({src_translated_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[\w.\-]+))""",
    """\safter\s+({session_duration}\d+)\s+seconds""",
    """\swith\s+({bytes_in}\d+)\s+bytes read""",
	"""\sand\s+({bytes_out}\d+)\s+bytes written"""
  ]
}
```