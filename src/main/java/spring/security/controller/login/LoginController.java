package spring.security.controller.login;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import spring.security.domain.Account;
import spring.security.security.service.AccountContext;

@Controller
@RequiredArgsConstructor
public class LoginController {

    @GetMapping("/login")
    public String login(String error, String exception, Model model) {

        model.addAttribute("error", error);
        model.addAttribute("exception", exception);

        return "/login";
    }

    @GetMapping("/logout")
    public String logout(HttpServletRequest request, HttpServletResponse response) {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication != null) {
            new SecurityContextLogoutHandler().logout(request, response, authentication);
        }
        return "redirect:/login";
    }

    @GetMapping("/denied")
    public String accessDenied(String exception, Model model) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        AccountContext account = (AccountContext) authentication.getPrincipal();
        model.addAttribute("username", account.getAccount().getUsername());
        model.addAttribute("exception", exception);

        return "user/login/denied";
    }
}
