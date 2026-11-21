import { Controller, Delete, Get, Param } from "@nestjs/common";
import { Public } from "./public.decorator";
import { UsersService } from "./users.service";

@Controller("admin/users")
export class AdminUsersController {
  constructor(private readonly users: UsersService) {}

  @Public()
  @Get()
  findAll() {
    return this.users.findAll();
  }

  @Delete(":id")
  remove(@Param("id") id: string) {
    return this.users.remove(id);
  }
}
