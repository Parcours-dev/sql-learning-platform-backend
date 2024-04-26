const mcd = {
    "database": {
        "name": "express_data",
        "tables": [
            {
                "name": "Departement",
                "columns": [
                    {"name": "DepartementID", "type": "int", "primaryKey": true},
                    {"name": "Nom", "type": "varchar", "length": 100},
                    {"name": "Budget", "type": "decimal", "precision": 10, "scale": 2}
                ]
            },
            {
                "name": "Employe",
                "columns": [
                    {"name": "EmployeID", "type": "int", "primaryKey": true, "autoIncrement": true},
                    {"name": "Nom", "type": "varchar", "length": 100},
                    {"name": "Salaire", "type": "decimal", "precision": 10, "scale": 2},
                    {"name": "DepartementID", "type": "int"},
                    {"name": "ManagerID", "type": "int"}
                ],
                "relations": [
                    {"type": "foreign", "table": "Departement", "column": "DepartementID"},
                    {"type": "foreign", "table": "Employe", "column": "ManagerID", "referenceColumn": "EmployeID"}
                ]
            },
            {
                "name": "Questions",
                "columns": [
                    {"name": "QuestionID", "type": "int", "primaryKey": true, "autoIncrement": true},
                    {"name": "Title", "type": "varchar", "length": 255},
                    {"name": "Description", "type": "text"},
                    {"name": "CorrectQuery", "type": "text"},
                    {"name": "Level", "type": "int"},
                    {"name": "Category", "type": "varchar", "length": 255},
                    {"name": "QuestionText", "type": "text", "nullable": true},
                    {"name": "Instructions", "type": "text", "nullable": true}
                ]
            },
            {
                "name": "Roles",
                "columns": [
                    {"name": "RoleID", "type": "int", "primaryKey": true, "autoIncrement": true},
                    {"name": "RoleName", "type": "varchar", "length": 255}
                ]
            },
            {
                "name": "UserResponses",
                "columns": [
                    {"name": "ResponseID", "type": "int", "primaryKey": true, "autoIncrement": true},
                    {"name": "UserID", "type": "int"},
                    {"name": "QuestionID", "type": "int"},
                    {"name": "UserQuery", "type": "text"},
                    {"name": "IsCorrect", "type": "tinyint"},
                    {"name": "SubmissionDate", "type": "datetime"}
                ],
                "relations": [
                    {"type": "foreign", "table": "Users", "column": "UserID"},
                    {"type": "foreign", "table": "Questions", "column": "QuestionID"}
                ]
            },
            {
                "name": "Users",
                "columns": [
                    {"name": "UserID", "type": "int", "primaryKey": true, "autoIncrement": true},
                    {"name": "Username", "type": "varchar", "length": 255},
                    {"name": "Email", "type": "varchar", "length": 255, "unique": true},
                    {"name": "PasswordHash", "type": "varchar", "length": 255},
                    {"name": "RegistrationDate", "type": "datetime"},
                    {"name": "RoleID", "type": "int"}
                ],
                "relations": [
                    {"type": "foreign", "table": "Roles", "column": "RoleID"}
                ]
            }
        ]
    }
};
module.exports = mcd;