<h1>Register</h1>
<form method="POST" action="/auth/tests.php">
    <input type="hidden" name="type" value="register">

    <label for="email">Email</label>
    <input type="email" name="email" />

    <label for="password">Password</label>
    <input type="password" name="password">

    <label for="confirm_password">Confirm Password</label>
    <input type="password" name="confirm_password">


    <button>Submit</button>
</form>


<h1>Login</h1>
<form method="POST" action="/auth/tests.php">
    <input type="hidden" name="type" value="login">
    <label for="email">Email</label>
    <input type="email" name="email" />

    <br>
    <br>
    <label for="password">Password</label>
    <input type="password" name="password">
    <br><br>
    <button>Submit</button>

</form>



<h1>Data</h1>
<form method="POST" action="/auth/tests.php">
    <input type="hidden" name="type" value="data">
    <button>Submit</button>
</form>