import { Document } from "mongoose";

export interface Users extends Document {
    name: string;
    email: string;
    password: string;
}