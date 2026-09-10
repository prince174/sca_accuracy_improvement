package com.example.golden;

import org.apache.commons.lang3.StringUtils;

public final class Application {
    private Application() {
    }

    public static void main(String[] args) {
        System.out.println(StringUtils.defaultIfBlank(System.getenv("GREETING"), "golden-ready"));
    }
}

