package com.example.sql;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import javax.servlet.http.HttpServletRequest;

public class SqlInjectionVulnerable {

    private static final String DB_URL = "jdbc:mysql://localhost/test";
    private static final String USER = "root";
    private static final String PASS = "password";

    public void getUserByName(HttpServletRequest request) throws Exception {
        String name = request.getParameter("name"); // source

        Connection connection = DriverManager.getConnection(DB_URL, USER, PASS);
        Statement statement = connection.createStatement();

        // Vulnerable: string concatenation with user input
        String query = "SELECT * FROM users WHERE username = '" + name + "'";
        ResultSet resultSet = statement.executeQuery(query); // FLAW

        connection.close();
    }
}
