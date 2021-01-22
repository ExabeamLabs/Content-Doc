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
```