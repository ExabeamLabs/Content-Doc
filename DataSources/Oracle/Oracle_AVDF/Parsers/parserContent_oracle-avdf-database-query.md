#### Parser Content
```Java
{
Name = oracle-avdf-database-query
  DataType = "database-query"
  Conditions = [  """ TARGET_TYPE="TABLE"""", """ SECURED_TARGET_NAME="""", """ SECURED_TARGET_TYPE=""""  ]
  Fields = ${Oracle-AVDFParserTemplates.s-oracle-avdf-events.Fields}[
    """TARGET_OBJECT="({table_name}[^"]+)"""",
    """COMMAND_CLASS="({db_operation}[^"]+)"""",
    """COMMAND_TEXT="(\s+|({db_query}[^"]+?))\s*("|$)""",
  ]
}
```