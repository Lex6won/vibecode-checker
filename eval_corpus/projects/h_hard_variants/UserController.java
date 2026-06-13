// 경계 프로브: Java/Spring — 언어 커버리지 측정용 (가짜 비밀번호)
package kr.go.gg.minwon;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;

public class UserController {

    private static final String DB_PASSWORD = "P@ssw0rdFAKE!";  // H-08 hardcoded password (java)

    public ResultSet findUser(Connection conn, String id) throws Exception {
        Statement stmt = conn.createStatement();
        String sql = "SELECT * FROM users WHERE id = " + id;  // H-09 sql concat (java)
        return stmt.executeQuery(sql);
    }
}
