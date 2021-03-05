#### Parser Content
```Java
{
Name = cef-cisco-firepower-dns-query
  DataType = "dns-query"
  Conditions = [ """|Cisco|""" , """|Firepower|""","""|CONNECTION STATISTICS|""", """destinationDnsDomain=""" ]
  Fields = ${CiscoParsersTemplates.cisco-firepower-events.Fields}[
  """destinationDnsDomain=({query}[^\s]+)""",
  ]
}
```