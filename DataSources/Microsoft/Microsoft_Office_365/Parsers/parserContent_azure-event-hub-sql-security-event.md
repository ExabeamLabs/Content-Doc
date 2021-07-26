#### Parser Content
```Java
{
Name = azure-event-hub-sql-security-event
  DataType = "database-query"
  Conditions = ["""ext_category=SQLSecurityAuditEvent""" ]
  Fields = ${MSParserTemplates.cef-azure-event-hub.Fields}[
  	""""host_name":"({host}.*?[^\\])"""",
  	""""application_name":"({app}.*?[^\\])"""",
  	""""statement":"({db_query}.*?[^\\])"""",
  	""""database_name":"({db_name}.*?[^\\])"""",
  	""""schema_name":"({schema}.*?[^\\])"""",
  	""""server_principal_name":"({server_group}.*?[^\\])"""",
  	""""server_principal_name":"({server_group}.*?[^\\])"""",
  	""""client_ip":"({src_ip}.*?[^\\])"""",
  	""""additional_information":"(""|({additional_info}.*?[^\\]))"""",
  ]
}
cef-azure-event-hub = {
  Vendor = Microsoft
  Product = Microsoft Azure
  Lms = Direct 
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [  """CEF:""",   """|Skyformation|SkyFormation Cloud Apps Security|""",   """destinationServiceName=Azure dproc=EventHub""" ]

```