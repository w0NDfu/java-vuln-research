package symbols;

class Parent {
    public String inherited(String input) { return input; }
    private String hidden(String input) { return input; }
}

class Container {
    class Worker extends Parent {
        public String select(String value) { return value; }
        public String select(int value) { return Integer.toString(value); }
        public void execute(String input) {
            class Local { String carry(String value) { return value; } }
            Runnable callback = new Runnable() {
                @Override public void run() {
                    System.out.println(input);
                }
            };
            callback.run();
        }
    }
    class Other { String select(String value) { return value; } }
    void first() {} void second() {}
}
