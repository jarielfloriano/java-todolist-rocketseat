package br.com.kobacode.todolist.filter;

import at.favre.lib.crypto.bcrypt.BCrypt;
import br.com.kobacode.todolist.user.IUserRepository;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Base64;

@Component
public class FilterTaskAuth extends OncePerRequestFilter {

    @Autowired
    private IUserRepository userRepository;

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {

        var serveletPath = request.getServletPath();
        if (serveletPath.equals("/tasks/")) {
            // Password decode
            var authorization = request.getHeader("Authorization");
            byte[] decode = Base64.getDecoder().decode(authorization.substring("Basic".length()).trim());
            var passwordString = new String(decode);
            String[] credentials = passwordString.split(":");
            String username = credentials[0];
            String password = credentials[1];

            // Validate user
            var user = this.userRepository.findByUsername(username);
            if (user == null) {
                response.sendError(401);
            }

            // Validar senha
            assert user != null;
            var verify = BCrypt.verifyer().verify(password.toCharArray(), user.getPassword());
            if (verify.verified) {
                request.setAttribute("idUser", user.getId());
                filterChain.doFilter(request, response);
            } else {
                response.sendError(401);
            }
        } else {
            filterChain.doFilter(request, response);
        }

    }
}
