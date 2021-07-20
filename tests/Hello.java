import java.io.FileWriter;
import java.io.IOException;

public class Hello {
    public static void main(String[] args) {
        int x = 42;
        for (int i = 0; i < 1000; i++) {
            x += x * 3 + i;
        }
        System.out.println(x);
    }
}