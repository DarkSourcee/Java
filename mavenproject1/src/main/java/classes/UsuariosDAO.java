package classes;

import org.mindrot.jbcrypt.BCrypt;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
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
            JOptionPane.showMessageDialog(null, "Adicionado com sucesso!","Sucesso", JOptionPane.INFORMATION_MESSAGE);
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
        
        String query = "SELECT id FROM usuario WHERE login = ? AND senha = ?";
        
        try{
            stmt = conn.prepareStatement(query);
            stmt.setString(1, login);
            stmt.setString(2, senha); 

            rs = stmt.executeQuery();
            
            String senhaCriptografada = BCrypt.hashpw(senha, BCrypt.gensalt(12));
            if (BCrypt.checkpw(senha, senhaCriptografada)) {
                existeUsuario = true;
            }
            
        }catch (SQLException e) {
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
            JOptionPane.showMessageDialog(null, "Adicionado com sucesso!","Sucesso", JOptionPane.INFORMATION_MESSAGE);
        } catch (SQLException e) {
            throw new RuntimeException(e);
        } finally {
            Conexao.closeConnection(conn, stmt);
        }
    }
}
