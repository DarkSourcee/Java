package classes;

import org.mindrot.jbcrypt.BCrypt;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import javax.swing.JOptionPane;

public class UsuariosDAO{
    public void create(Usuarios usuarios) {
        Connection conn = Conexao.getConnection();
        PreparedStatement stmt = null;
        
        String query = "INSERT INTO usuario (nome, email, login, senha) VALUES (?, ?, ?, ?)";
        
        try {
            String senhaCriptografada = BCrypt.hashpw(usuarios.getSenha(), BCrypt.gensalt());
            
            stmt = conn.prepareStatement(query);
            stmt.setString(1, usuarios.getNome());
            stmt.setString(2, usuarios.getEmail());
            stmt.setString(3, usuarios.getLogin());
            stmt.setString(4, senhaCriptografada);
            stmt.executeUpdate();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        } finally {
            Conexao.closeConnection(conn, stmt);
        }
    }
    
    public boolean usuarioExistente(String login, String nome, String email) {
        Connection conn = Conexao.getConnection();
        PreparedStatement stmt = null;
        ResultSet rs = null;
        
        boolean existeUsuario = false;
        
        String query = "SELECT id FROM usuario WHERE login = ? OR nome = ? OR email = ?";
        
        try{
            stmt = conn.prepareStatement(query);
            stmt.setString(1, login);
            stmt.setString(2, nome);
            stmt.setString(3, email);

            rs = stmt.executeQuery();

            if (rs.next()) {
                existeUsuario = true;
            }
            
        }catch (SQLException e) {
            throw new RuntimeException(e);
        } finally {
            Conexao.closeConnection(conn, stmt, rs);
        }
        return existeUsuario;
    }
    
    public boolean verificaLogin(String login, String senha) {
        Connection conn = Conexao.getConnection();
        PreparedStatement stmt = null;
        ResultSet rs = null;

        boolean existeUsuario = false;

        String query = "SELECT senha FROM usuario WHERE login = ?";

        try {
            stmt = conn.prepareStatement(query);
            stmt.setString(1, login);

            rs = stmt.executeQuery();

            if (rs.next()) {
                String senhaArmazenada = rs.getString("senha");

                // Verifica se a senha fornecida pelo usuário corresponde à senha armazenada no banco de dados após a descriptografia
                if (BCrypt.checkpw(senha, senhaArmazenada)) {
                    existeUsuario = true;
                }
            }

        } catch (SQLException e) {
            throw new RuntimeException(e);
        } finally {
            Conexao.closeConnection(conn, stmt, rs);
        }

        return existeUsuario;
    }
    
    public void delete(Usuarios usuarios) {
        Connection conn = Conexao.getConnection();
        PreparedStatement stmt = null;
        
        String query = "DELETE FROM usuario WHERE id = ?";
        
        try {
            stmt = conn.prepareStatement(query);
            stmt.setInt(1, usuarios.getId());
            stmt.executeUpdate();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        } finally {
            Conexao.closeConnection(conn, stmt);
        }
    }
    
    public void update(Usuarios usuarios) throws SQLException {
        Connection conn = Conexao.getConnection();
        PreparedStatement stmt = null;
        
        String query = "UPDATE usuario SET nome = ?, email = ?, login = ?, senha = ? WHERE id = ?";
        
        String senhaCriptografada = BCrypt.hashpw(usuarios.getSenha(), BCrypt.gensalt());
        try {
            stmt = conn.prepareStatement(query);
            stmt.setString(1, usuarios.getNome());
            stmt.setString(2, usuarios.getEmail());
            stmt.setString(3, usuarios.getLogin());
            stmt.setString(4, senhaCriptografada);
            stmt.setInt(5, usuarios.getId());
            stmt.executeUpdate();
        }catch (SQLException e) {
            throw new RuntimeException(e);
        } finally {
            Conexao.closeConnection(conn, stmt);
        }
    }
    
    public Usuarios findById(Integer id) {
        Connection conn = Conexao.getConnection();
        PreparedStatement stmt = null;
        ResultSet rs = null;

        String query = "SELECT id, nome, email, login FROM usuario WHERE id = ?";

        try {
            stmt = conn.prepareStatement(query);
            stmt.setInt(1, id);
            rs = stmt.executeQuery();

            if (rs.next()) { // Verifica se há pelo menos um resultado
                Usuarios usuarios = new Usuarios();
                usuarios.setId(rs.getInt("id")); // Use rs.getInt() para recuperar o ID
                usuarios.setNome(rs.getString("nome"));
                usuarios.setEmail(rs.getString("email"));
                usuarios.setLogin(rs.getString("login"));
                return usuarios;
            } else {
                return null;
            }
        } catch (SQLException e) {
            throw new RuntimeException(e);
        } finally {
            Conexao.closeConnection(conn, stmt);
        }
    }

    
    public List<Usuarios> findByName(String nome) {
        Connection conn = Conexao.getConnection();
        PreparedStatement stmt = null;
        ResultSet rs = null;
        
        String query = "SELECT * FROM usuario WHERE nome like ?";
        
        List<Usuarios> usuarios = new ArrayList<>();
        
        try {
            stmt = conn.prepareStatement(query);
            stmt.setString(1, "%" + nome + "%");
            rs = stmt.executeQuery();
            
            while (rs.next()) {
                Usuarios usu = new Usuarios();
                
                usu.setId(rs.getInt("id"));
                usu.setNome(rs.getString("nome"));
                usu.setEmail(rs.getString("email"));
                usu.setLogin(rs.getString("login"));
                usuarios.add(usu);
            }
        } catch (SQLException e) {
            JOptionPane.showMessageDialog(null, "Erro: " + e.getMessage(),"Erro", JOptionPane.INFORMATION_MESSAGE);
            throw new RuntimeException(e);
        } finally {
            Conexao.closeConnection(conn, stmt, rs);
        }
        return usuarios;
    }
    
    public List<Usuarios> findAll() {
        Connection conn = Conexao.getConnection();
        PreparedStatement stmt = null;
        ResultSet rs = null;
        
        String query = "SELECT * FROM usuario";
        
        List<Usuarios> usuarios = new ArrayList<>();
        
        try {
            stmt = conn.prepareStatement(query);
            rs = stmt.executeQuery();
            
            while (rs.next()) {
                Usuarios usu = new Usuarios();
                
                usu.setId(rs.getInt("id"));
                usu.setNome(rs.getString("nome"));
                usu.setEmail(rs.getString("email"));
                usu.setLogin(rs.getString("login"));
                usuarios.add(usu);
            }
        } catch (SQLException e) {
            JOptionPane.showMessageDialog(null, "Erro: " + e.getMessage(),"Erro", JOptionPane.INFORMATION_MESSAGE);
            throw new RuntimeException(e);
        } finally {
            Conexao.closeConnection(conn, stmt, rs);
        }
        return usuarios;
    }
}
